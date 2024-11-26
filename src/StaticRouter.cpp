#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"
#include <iostream>

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    /* ORDER OF OPERATIONS */

    // Parse for whether its an IP packet or ARP packet (Grab ethernet header)
    sr_ethernet_hdr_t eth_hdr;
    memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
    if (eth_hdr.ether_type == htons(ethertype_arp)) { // If ARP packet
        /*** ---- IF ARP Packet ---- ***/
        sr_arp_hdr_t arp_hdr;
        memcpy(&arp_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_arp_hdr_t));
        if (arp_hdr.ar_op == htons(arp_op_request)) { // If ARP request
            uint32_t target_ip = arp_hdr.ar_tip;
            RoutingInterface inter = routingTable->getRoutingInterface(iface);
            if (target_ip == inter.ip) {
                // changes the ethernet packet 
                mac_addr insert = inter.mac;
                memcpy(eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
                memcpy(eth_hdr.ether_shost, &insert, ETHER_ADDR_LEN);
                // changes needed for the arp header
                arp_hdr.ar_op = htons(arp_op_reply);
                arp_hdr.ar_tip = arp_hdr.ar_sip;
                arp_hdr.ar_sip = inter.ip;
                memcpy(arp_hdr.ar_tha, arp_hdr.ar_sha, ETHER_ADDR_LEN);
                memcpy(arp_hdr.ar_sha, &insert, ETHER_ADDR_LEN);

                memcpy(packet.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));
                memcpy(packet.data() + sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));
                packetSender->sendPacket(packet, iface);
                return;
            }
            else {
                return;
            }
        }
        else { // If arp reply (arp_hdr.ar_op == arp_op_reply)
            mac_addr sender_mac;
            memcpy(&sender_mac, arp_hdr.ar_sha, ETHER_ADDR_LEN);
            uint32_t sender_ip = arp_hdr.ar_sip;
            arpCache->addEntry(sender_ip, sender_mac);
            return;
            // tick() should handle sending queued packets
        }
        // send packets in queue
        return;
    }

    /*** ---- IF IP Packet ---- ***/
    // 1. Calculate checksum and compare to original, also check if ttl == 0 when we receive it
    sr_ip_hdr_t ip_hdr;
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    if (ip_hdr.ip_ttl == 0) {
        // ignore IP packet if TTL is already 0
        return;
    }
    uint16_t old_sum = ip_hdr.ip_sum;
    ip_hdr.ip_sum = htons(0);
    uint16_t chksum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t));
    if (chksum != old_sum) {
        std::cout << "Checksum check failed" << std::endl; // TODO: Delete me 
        return;
    }
    
    // 2. Check if the destination IP is one of our interfaces IP addresses
    //    If it is:
    //          If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo reply to the sending host.
    //          If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host.
    //          Otherwise, ignore the packet.
    std::unordered_map<std::string, RoutingInterface> interfaces = routingTable->getRoutingInterfaces();
    bool match = false;
    for (auto it = interfaces.begin(); it != interfaces.end(); it++) {
        if (it->second.ip == ip_hdr.ip_dst) {
            match = true;
            break;
        }
    }

    if (match) {
        /* 
        1. If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo reply to the sending host.
        2. If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host.
        3. Otherwise, ignore the packet.
        */  

       // This means that the packet that came into one of our routers IP's is an ICMP msg
       // According to spec we only need to process if its an echo response.  
       // This should accomplish bullet point 1 
        if (ip_hdr.ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t icmp_hdr;
            memcpy(&icmp_hdr, packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_hdr_t));
            if (icmp_hdr.icmp_type != 8 && icmp_hdr.icmp_code != 0) {
                return;
            }
            // now need to verify that the checksum is valid
            uint16_t prev_sum = icmp_hdr.icmp_sum;
            icmp_hdr.icmp_sum = htons(0);
            uint16_t checksum = cksum(&icmp_hdr,sizeof(sr_icmp_hdr_t));
            if (prev_sum != checksum) {
                return;
            }
            icmp_hdr.icmp_sum = checksum;

            // grab the destination mac address of icmp packet (original sender's mac)
            mac_addr dest_mac;
            memcpy(&dest_mac, eth_hdr.ether_shost, ETHER_ADDR_LEN);
            Packet icmp_packet = createICMPPacket(dest_mac, iface, 0, 0, packet);

            packetSender->sendPacket(packet, iface);
            return;
        }
        else if (ip_hdr.ip_p == ip_protocol_tcp || ip_hdr.ip_p == ip_protocol_udp) {
            // Send ICMP port unreachable (type 3, code 3)
            mac_addr dest_mac; // host's mac address we are sending to
            memcpy(&dest_mac, eth_hdr.ether_shost, ETHER_ADDR_LEN);
            Packet icmp_packet = createICMPPacket(dest_mac, iface, 3, 3, packet);
            packetSender->sendPacket(icmp_packet, iface);
            return;
            
        }
        else { // Any other packet not 
            return;
        }
    }
    
    // 3. Decrement TTL by 1, and recompute checksum over modified header
    ip_hdr.ip_ttl--; // Decrement TTL
    if (ip_hdr.ip_ttl == 0) {
        // Send ICMP Time exceeded (type 11, code 0)
        mac_addr dest_mac; // host's mac address we are sending to
        memcpy(dest_mac.data(), eth_hdr.ether_shost, ETHER_ADDR_LEN);
        Packet icmp_packet = createICMPPacket(dest_mac, iface, 11, 0, packet);
        packetSender->sendPacket(icmp_packet, iface);
        return;
    }
    ip_hdr.ip_sum = htons(0);
    ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t)); // computing new checksum
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    
    // 4. Use getRoutingEntry() to determine next hop router of destination IP address in packet header
    ip_addr dest_ip = ip_hdr.ip_dst;
    std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(dest_ip); // using longest prefix match
    if (!entry.has_value()) {
        // Send ICMP Destination net unreachable (type 3, code 0)
        mac_addr dest_mac; // host's mac address we are sending to
        memcpy(dest_mac.data(), eth_hdr.ether_shost, ETHER_ADDR_LEN);
        Packet icmp_packet = createICMPPacket(dest_mac, iface, 3, 0, packet);
        packetSender->sendPacket(icmp_packet, iface);
        return;
    }
    
    // 5. Check ARP cache for next-hop MAC address ** ARP Cache Logic here **
    std::optional<mac_addr> dest_mac = arpCache -> getEntry(entry->dest);
    if (!dest_mac.has_value()) {
        arpCache->queuePacket(entry->dest, packet, iface);
    }
    else { // Forward the packet
       
        sr_ethernet_hdr_t eth_hdr;
        memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
        // Change the mac source address to next hop router iface mac
        mac_addr source_mac = routingTable->getRoutingInterface(entry->iface).mac;
        memcpy(&eth_hdr.ether_shost, source_mac.data(), ETHER_ADDR_LEN);
        // Change the dest source address to the return mac address from arpCache
        memcpy(&eth_hdr.ether_dhost, dest_mac->data(), ETHER_ADDR_LEN);   

        // Copy new ethernet header back into packet
        memcpy(packet.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));

        // Send out updated packet
        packetSender->sendPacket(packet, entry->iface);
    }
    
}


Packet StaticRouter::createICMPPacket(const mac_addr dest_mac, const std::string& iface, const uint8_t type, const uint8_t code, Packet original_pac) {
    Packet ICMP_packet;
    
    // Create ethernet header information at the front of the packet
    sr_ethernet_hdr_t eth_hdr;
    eth_hdr.ether_type = htons(sr_ethertype::ethertype_ip); // IP protocol type
    memcpy(&eth_hdr.ether_dhost, dest_mac.data(), ETHER_ADDR_LEN);
    mac_addr sender_mac = routingTable->getRoutingInterface(iface).mac;
    memcpy(&eth_hdr.ether_shost, sender_mac.data(), ETHER_ADDR_LEN);

    ICMP_packet.resize(sizeof(sr_ethernet_hdr_t));
    memcpy(ICMP_packet.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));

    // Create IP header information
    sr_ip_hdr_t ip_header;
    memset(&ip_header, 0, sizeof(sr_ip_hdr_t));
    memcpy(&ip_header, original_pac.data() + sizeof(sr_ethernet_hdr), sizeof(sr_ip_hdr_t));

    // Set fields for an ICMP packet
    if (type == 0) {
        // flips the Ip src and dst address
        ip_addr old_ip_dst = ip_header.ip_dst;
        ip_header.ip_dst = ip_header.ip_src;
        ip_header.ip_src = old_ip_dst;
    } 
    else {ip_header.ip_dst = ip_header.ip_src;};  // Destination IP address is original pac's source ip for type 3 and 11

    // Calculate checksum
    ip_header.ip_sum = htons(0); // Ensure checksum field is 0 before calculating
    ip_header.ip_sum = cksum(&ip_header, sizeof(sr_ip_hdr_t));

    ICMP_packet.resize(sizeof(sr_ip_hdr_t));
    memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t), &ip_header, sizeof(sr_ip_hdr_t));
    
    // Type 0
    if (type == 0) {
        sr_icmp_hdr_t icmp_t0_hdr;
        icmp_t0_hdr.icmp_type = type;   // type == 0
        icmp_t0_hdr.icmp_code = code;
        // Calculate checksum
        icmp_t0_hdr.icmp_sum = htons(0);
        icmp_t0_hdr.icmp_sum = cksum(&icmp_t0_hdr, sizeof(sr_icmp_hdr_t));

        // Add to packet
        ICMP_packet.resize(sizeof(sr_icmp_hdr_t));
        memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_t0_hdr, sizeof(sr_icmp_hdr_t));
    }

    // Type 3
    else if (type == 3) {
        sr_icmp_t3_hdr_t icmp_t3_hdr;
        icmp_t3_hdr.icmp_type = type;   // type == 3
        icmp_t3_hdr.icmp_code = code;
        icmp_t3_hdr.unused = htons(0);
        icmp_t3_hdr.next_mtu = htons(0);
        // Calculate checksum
        icmp_t3_hdr.icmp_sum = htons(0);
        icmp_t3_hdr.icmp_sum = cksum(&icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
        // Set data to be original pac's IP header and first 8 bytes of payload
        memcpy(icmp_t3_hdr.data, original_pac.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + std::min(static_cast<size_t>(8), original_pac.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));
        
        // Add to packet
        ICMP_packet.resize(sizeof(sr_icmp_t3_hdr_t));
        memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    }

    // Type 11
    else if (type == 11) {

        sr_icmp_t11_hdr_t icmp_t11_hdr;
        icmp_t11_hdr.icmp_type = type;
        icmp_t11_hdr.icmp_code = code;
        icmp_t11_hdr.unused = htons(0);
        // Calculate checksum
        icmp_t11_hdr.icmp_sum = htons(0);
        icmp_t11_hdr.icmp_sum = cksum(&icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));
        // Set data to be original pac's IP header and first 8 bytes of payload
        memcpy(icmp_t11_hdr.data, original_pac.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + std::min(static_cast<size_t>(8), original_pac.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));

        // Add to packet
        ICMP_packet.resize(sizeof(sr_icmp_t11_hdr_t));
        memcpy(ICMP_packet.data(), &icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));
    }
}