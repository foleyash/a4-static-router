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

    spdlog::info("**** HANDLING NEW PACKET ****");

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
            spdlog::info("received arp request...");
            uint32_t target_ip = arp_hdr.ar_tip;
            RoutingInterface inter = routingTable->getRoutingInterface(iface);
            if (target_ip == inter.ip) {
                spdlog::info("the target ip matches the interface ip...");
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
                spdlog::info("Sending an ARP reply for IP: {}", ipToString(target_ip));
                packetSender->sendPacket(packet, iface);
                return;
            }
            else {
                spdlog::info("the target ip DOES NOT matc the interface ip...");
                return;
            }
        }
        else { // If arp reply (arp_hdr.ar_op == arp_op_reply)
            uint32_t target_ip = arp_hdr.ar_tip;
            RoutingInterface inter = routingTable->getRoutingInterface(iface);
            if (target_ip == inter.ip) {
                spdlog::info("received arp reply...");
                mac_addr sender_mac;
                memcpy(&sender_mac, arp_hdr.ar_sha, ETHER_ADDR_LEN);
                uint32_t sender_ip = arp_hdr.ar_sip;
                arpCache->addEntry(sender_ip, sender_mac);
                return;
            }
            else {
                spdlog::info("the target ip DOES NOT match the interface ip...");
                return;
            }
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
        spdlog::info("Checksum failed!");
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

       spdlog::info("The packet destination is our own");
        if (ip_hdr.ip_p == ip_protocol_icmp) {
            spdlog::info("recieved icmp request...");
            sr_icmp_hdr_t icmp_hdr;
            void * icmp_remaining_buf = packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
            size_t icmp_len = packet.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); // Length of icmp header w/ type, code, sum, id, seq num, data
            size_t icmp_remaining_len = packet.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); // Length of remaining id, seq num, data
            std::vector<uint8_t> icmp_hdr_buf(icmp_len, 0); // Initialize buffer of zeros of length of icmp header
            memcpy(&icmp_hdr, packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_hdr_t)); // Copy contents of type, code, sum
            if (icmp_hdr.icmp_type != 8 && icmp_hdr.icmp_code != 0) {
                spdlog::info("Not an ICMP echo request packet, dropping...");
                return;
            }
            // now need to verify that the checksum is valid
            uint16_t prev_sum = icmp_hdr.icmp_sum;
            icmp_hdr.icmp_sum = htons(0);
            memcpy(icmp_hdr_buf.data(), &icmp_hdr, sizeof(sr_icmp_hdr_t)); // Copy contents of type, code, sum
            memcpy(icmp_hdr_buf.data() + sizeof(sr_icmp_hdr_t), icmp_remaining_buf, icmp_remaining_len);
            uint16_t checksum = cksum(icmp_hdr_buf.data(), icmp_hdr_buf.size()); // May be calculating checksum on incorrect portion of ICMP header (according to ED #989)
            if (prev_sum != checksum) {
                spdlog::info("ICMP packet's checksum failed!");
                spdlog::info("Previous sum: {:#x}", prev_sum);
                spdlog::info("New checksum: {:#x}", checksum);
                return;
            }
            icmp_hdr.icmp_sum = checksum;

            // grab the destination mac address of icmp packet (original sender's mac)
            mac_addr dest_mac;
            memcpy(&dest_mac, eth_hdr.ether_shost, ETHER_ADDR_LEN);
            Packet icmp_packet = createICMPPacket(dest_mac, iface, 0, 0, packet);
            spdlog::info("ICMP packet size: {}", icmp_packet.size());
            print_hdrs(icmp_packet.data(), icmp_packet.size());

            packetSender->sendPacket(icmp_packet, iface);
            return;
        }
        else if (ip_hdr.ip_p == ip_protocol_tcp || ip_hdr.ip_p == ip_protocol_udp) {
            // Send ICMP port unreachable (type 3, code 3)
            spdlog::info("tcp or udp packet detected, sending ICMP port unreachable (type 3, code 3)...");
            std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(ip_hdr.ip_src);
            mac_addr dest_mac; // host's mac address we are sending to
            memcpy(&dest_mac, eth_hdr.ether_shost, ETHER_ADDR_LEN);
            Packet icmp_packet = createICMPPacket(dest_mac, entry->iface, 3, 3, packet);
            packetSender->sendPacket(icmp_packet, entry->iface);
            return;
            
        }
        else { // Any other packet not 
            spdlog::info("other packet received, dropping");
            return;
        }
    }
    spdlog::info("The packet is meant to be forwarded somewhere else");
    
    // 3. Decrement TTL by 1, and recompute checksum over modified header
    spdlog::info("TTL: {}", ip_hdr.ip_ttl);
    ip_hdr.ip_ttl--; // Decrement TTL
    if (ip_hdr.ip_ttl == 0) {
        // Send ICMP Time exceeded (type 11, code 0)
        mac_addr dest_mac; // host's mac address we are sending to
        memcpy(dest_mac.data(), eth_hdr.ether_shost, ETHER_ADDR_LEN);
        Packet icmp_packet = createICMPPacket(dest_mac, iface, 11, 0, packet);
        packetSender->sendPacket(icmp_packet, iface);
        return;
    }
    spdlog::info("Made it to here right before memcpy");
    ip_hdr.ip_sum = htons(0);
    ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t)); // computing new checksum
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    
    // 4. Use getRoutingEntry() to determine next hop router of destination IP address in packet header
    ip_addr dest_ip = ip_hdr.ip_dst;
    std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(dest_ip); // using longest prefix match
    spdlog::info("Successfuly got the routing entry");
    if (!entry.has_value()) {
        // Send ICMP Destination net unreachable (type 3, code 0)
        spdlog::info("no matching routing entry, sending ICMP denstination net unreachable (type 3, code 0)");
        mac_addr dest_mac; // host's mac address we are sending to
        memcpy(dest_mac.data(), eth_hdr.ether_shost, ETHER_ADDR_LEN);
        Packet icmp_packet = createICMPPacket(dest_mac, iface, 3, 0, packet);
        packetSender->sendPacket(icmp_packet, iface);
        return;
    }
    
    // 5. Check ARP cache for next-hop MAC address ** ARP Cache Logic here **
    std::optional<mac_addr> dest_mac = arpCache -> getEntry(entry->dest);
    if (!dest_mac.has_value()) {
        spdlog::info("No arp cache entry for IP: {}, queueing packet...", ipToString(entry->dest));
        arpCache->queuePacket(entry->gateway, packet, entry->iface);
    }
    else { // Forward the packet
        spdlog::info("Forwarding packet to MAC address");
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


Packet StaticRouter::createICMPPacket(const mac_addr dest_mac, const std::string iface, const uint8_t type, const uint8_t code, Packet original_pac) {
    Packet ICMP_packet;
    
    // Create ethernet header information at the front of the packet
    sr_ethernet_hdr_t eth_hdr;
    eth_hdr.ether_type = htons(sr_ethertype::ethertype_ip); // IP protocol type
    memcpy(&eth_hdr.ether_dhost, dest_mac.data(), ETHER_ADDR_LEN);
    mac_addr sender_mac = routingTable->getRoutingInterface(iface).mac;
    memcpy(&eth_hdr.ether_shost, sender_mac.data(), ETHER_ADDR_LEN);
    ICMP_packet.resize(ICMP_packet.size() + sizeof(sr_ethernet_hdr_t));
    memcpy(ICMP_packet.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));

    // Create IP header information
    // *** UPDATED THIS ****
    /*
        - I think that we need to generate a new IP header for each ICMP packet created, rather than copy the existing header (according to GPT)
    */
    sr_ip_hdr_t ip_header;
    memcpy(&ip_header, original_pac.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t)); // Copy in entire ip header from original pac, then modify certain attributes

    ip_header.ip_tos = 0;
    size_t icmp_t0_len = original_pac.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    ip_header.ip_len = htons(sizeof(sr_ip_hdr_t) + ((type == 0) ? icmp_t0_len
                                                : (type == 3) ? sizeof(sr_icmp_t3_hdr_t)
                                                : sizeof(sr_icmp_t11_hdr_t))); // IP header + payload size
    ip_header.ip_id = htons(0x1234);           // use random value since fragmentation is not used
    ip_header.ip_off = htons(0);               // Set to 0 to not use fragmentation
    ip_header.ip_ttl = 64;
    ip_header.ip_p = sr_ip_protocol::ip_protocol_icmp;
    // memset(&ip_header, 0, sizeof(sr_ip_hdr_t));
    // memcpy(&ip_header, original_pac.data() + sizeof(sr_ethernet_hdr), sizeof(sr_ip_hdr_t));

    // Set fields for an ICMP packet
    // flips the Ip src and dst address
    if(type == 0) {
        ip_addr old_ip_dst = ip_header.ip_dst;
        ip_header.ip_dst = ip_header.ip_src;
        ip_header.ip_src = old_ip_dst;
    }
    else {
        // call get routing interface  put that as the src ip 
        ip_header.ip_dst = ip_header.ip_src;
        ip_header.ip_src = routingTable->getRoutingInterface(iface).ip; // Set source as iface's ip the packet came in on (and goes out on)
    }
    

    // Calculate checksum
    ip_header.ip_sum = htons(0); // Ensure checksum field is 0 before calculating
    ip_header.ip_sum = cksum(&ip_header, sizeof(sr_ip_hdr_t));

    ICMP_packet.resize(ICMP_packet.size() + sizeof(sr_ip_hdr_t));
    memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t), &ip_header, sizeof(sr_ip_hdr_t));
    
    // Type 0
    if (type == 0) {
        sr_icmp_hdr_t icmp_t0_hdr;
        icmp_t0_hdr.icmp_type = type;   // type == 0
        icmp_t0_hdr.icmp_code = code;
        // size_t icmp_len = original_pac.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        // std::vector<uint8_t> icmp_hdr_buf(icmp_len, 0);
        // memcpy(icmp_hdr_buf.data(), &original_pac + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_len);
        spdlog::info("Updated code 2 has run");

        // Grab id, seq num, data from original_pac
        void * icmp_remaining_buf = original_pac.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        size_t icmp_len = original_pac.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); // Length of icmp header w/ type, code, sum, id, seq num, data
        size_t icmp_remaining_len = original_pac.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); // Length of remaining id, seq num, data
        std::vector<uint8_t> icmp_hdr_buf(icmp_len, 0); // Initialize buffer of zeros of length of icmp header

        // Calculate checksum
        icmp_t0_hdr.icmp_sum = htons(0);
 
        memcpy(icmp_hdr_buf.data(), &icmp_t0_hdr, sizeof(sr_icmp_hdr_t)); // Copy contents of type, code, sum
        memcpy(icmp_hdr_buf.data() + sizeof(sr_icmp_hdr_t), icmp_remaining_buf, icmp_remaining_len); // copy contents of id, seq num , data

        icmp_t0_hdr.icmp_sum = cksum(icmp_hdr_buf.data(), icmp_hdr_buf.size());

        memcpy(icmp_hdr_buf.data(), &icmp_t0_hdr, sizeof(sr_icmp_hdr_t));

        // Add to packet
        ICMP_packet.resize(ICMP_packet.size() + icmp_hdr_buf.size());
        memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_hdr_buf.data(), icmp_hdr_buf.size());
    }

    // Type 3
    else if (type == 3) {
        sr_icmp_t3_hdr_t icmp_t3_hdr;
        icmp_t3_hdr.icmp_type = type;   // type == 3
        icmp_t3_hdr.icmp_code = code;
        icmp_t3_hdr.unused = htons(0);
        icmp_t3_hdr.next_mtu = htons(0);
        
        // Set data to be original pac's IP header and first 8 bytes of payload
        memcpy(icmp_t3_hdr.data, original_pac.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + std::min(static_cast<size_t>(8), original_pac.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));
        
        // Calculate checksum
        icmp_t3_hdr.icmp_sum = htons(0);
        icmp_t3_hdr.icmp_sum = cksum(&icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

        // Add to packet
        ICMP_packet.resize(ICMP_packet.size() + sizeof(sr_icmp_t3_hdr_t));
        memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    }

    // Type 11
    else if (type == 11) {

        sr_icmp_t11_hdr_t icmp_t11_hdr;
        icmp_t11_hdr.icmp_type = type;
        icmp_t11_hdr.icmp_code = code;
        icmp_t11_hdr.unused = htonl(0);
        
        // Set data to be original pac's IP header and first 8 bytes of payload
        memcpy(icmp_t11_hdr.data, original_pac.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + std::min(static_cast<size_t>(8), original_pac.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));

        // Calculate checksum
        icmp_t11_hdr.icmp_sum = htons(0);
        icmp_t11_hdr.icmp_sum = cksum(&icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));

        // Add to packet
        ICMP_packet.resize(ICMP_packet.size() + sizeof(sr_icmp_t11_hdr_t));
        memcpy(ICMP_packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));
    }

    return ICMP_packet;
}