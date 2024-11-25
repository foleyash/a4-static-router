#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

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

    // Parse for whether its an IP packet or ARP packet
    sr_ethernet_hdr_t eth_hdr;
    memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
    if (ntohs(eth_hdr.ether_type) == ethertype_arp) {
        /*** ---- IF ARP Packet ---- ***/

        // send packets in queue
    }

    /*** ---- IF IP Packet ---- ***/
    // 1. Calculate checksum and compare to original
    sr_ip_hdr_t ip_hdr;
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    uint16_t old_sum = ip_hdr.ip_sum;
    ip_hdr.ip_sum = htons(0);
    uint16_t chksum = ntohs(cksum(&ip_hdr, sizeof(sr_ip_hdr_t)));
    if (chksum != ntohs(old_sum)) {
        // Maybe message here 
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
        if (it->second.ip == ntohl(ip_hdr.ip_dst)) {
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
            uint16_t prev_sum = ntohs(icmp_hdr.icmp_sum);
            icmp_hdr.icmp_sum = htons(0);
            uint16_t checksum = ntohs(cksum(&icmp_hdr,sizeof(sr_icmp_hdr_t)));
            if (prev_sum != checksum) {
                return;
            }
            icmp_hdr.icmp_type = 0;
            icmp_hdr.icmp_sum = cksum(&icmp_hdr, sizeof(sr_icmp_hdr_t));

            mac_addr old_dest;
            memcpy(&old_dest, eth_hdr.ether_dhost, ETHER_ADDR_LEN);
            memcpy(eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr.ether_shost, &old_dest, ETHER_ADDR_LEN);

            uint32_t oldIpDst = ip_hdr.ip_dst;
            ip_hdr.ip_dst = ip_hdr.ip_src;
            ip_hdr.ip_src = oldIpDst;
            memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
            memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
            memcpy(&icmp_hdr, packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_hdr_t));
            packetSender->sendPacket(packet,iface);
        }
    }
    
    // 3. Decrement TTL by 1, and recompute checksum over modified header
    ip_hdr.ip_ttl--; // Decrement TTL
    if (ip_hdr.ip_ttl == 0) {
        // Send ICMP Time exceeded (type 11, code 0)
        return;
    }
    ip_hdr.ip_sum = htons(0);
    ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t));
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    
    // 4. Use getRoutingEntry() to determine next hop router of destination IP address in packet header
    ip_addr dest_ip = ntohl(ip_hdr.ip_dst);
    std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(dest_ip); // using longest prefix match
    if (!entry.has_value()) {
        // Send ICMP Destination net unreachable (type 3, code 0)
        return;
    }
    // 5. Check ARP cache for next-hop MAC address ** ARP Cache Logic here **
    std::optional<mac_addr> mac = arpCache -> getEntry(entry->dest);
    if (!mac.has_value()) {
        arpCache->queuePacket(entry->dest, packet, iface);
    }
    else {
        // Forward the packet
    }
    
    // NOTE: if there is a packet destined to us that has a TCP or UDP payload, we send an ICMP port unreachable to the sending host
}
