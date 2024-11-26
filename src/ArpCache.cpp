#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"


ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) { 
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}


void ArpCache::tick() {
    std::unique_lock lock(mutex);
    // Iterate through all outstanding requests
    for (auto it = requests.begin(); it != requests.end(); it++) {
        //  If (currTime - request.lastSent) >= timeout, retransmit packet
        auto now = std::chrono::steady_clock::now();
        
        ArpRequest current_request = it->second;
        std::optional<mac_addr> check = getEntry(current_request.ip);
        if (current_request.timesSent >= 7 && !check.has_value()) {
            // send ICMP message and use the PACKED attribute
            for (const auto& awaiting_packet : current_request.awaitingPackets) {
                // Grab the routing interface the awaiting packet came in on
                sr_ethernet_hdr_t eth_hdr;
                memcpy(&eth_hdr, awaiting_packet.packet.data(), sizeof(sr_ethernet_hdr_t));
                sr_ip_hdr_t ip_hdr;
                memcpy(&ip_hdr, awaiting_packet.packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
                mac_addr senderMac;
                memcpy(&senderMac, eth_hdr.ether_shost, ETHER_ADDR_LEN);
                ip_addr sender_ip = ip_hdr.ip_src;
                RoutingInterface ri = icmps[sender_ip]; // Use sender's ip to grab routing interface to send back on
                
                // Construct ICMP packet and send
                Packet icmp_packet = createICMPPacket(senderMac, ri.name, 3, 1, awaiting_packet.packet);
                packetSender->sendPacket(icmp_packet, ri.name);
            }
            
            it = requests.erase(it); // (will also get rid of queued packets for this request)
        }
        else if (now - current_request.lastSent >= std::chrono::seconds(1) && !check.has_value()) {
            // Resend packet 
            ip_addr ip = current_request.ip;
            std::string iface = interfaces[ip];
            Packet pac = arp_packets[ip];
            packetSender->sendPacket(pac, iface);
            it->second.timesSent++;
        }
        else if(check.has_value()) {
            sendQueuedPackets(current_request.ip, check.value());
        }
    }

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    
    ArpEntry entry = {ip, mac, std::chrono::steady_clock::now()};
    entries.insert({ip, entry});
}

// Input: ip is the next hop ip address (network order)
std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    auto entry = entries.find(ip);
    if (entry != entries.end()) {
        return entry->second.mac;
    }

    return std::nullopt; // Return nothing if no entry for this ip exists
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    /*This logic right here is to ensure that we store the interface on which a Packet is coming in on
      We accomplish this by:
      - First taking apart the packet and seeing the destination host
      - We then compare this destination host with all of our own interfaces (as one of these must match)
      - Then we finally store for this Packet the routing Interface on which it came in on in a map called icmps
      - This map can then be called for in other functions when needing to send back and icmp message.
      - This also allows us to keep use of the definition we had where iface will be the NEXT HOP iface not the iface on which it came in on
    */

    sr_ethernet_hdr_t eth_hdr;
    memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t ip_hdr;
    memcpy(&ip_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    mac_addr incomingMac;
    memcpy(&incomingMac, eth_hdr.ether_dhost, ETHER_ADDR_LEN);
    const std::unordered_map<std::string, RoutingInterface> check = routingTable->getRoutingInterfaces();
    for (const auto& pair : check) {
        if (pair.second.mac == incomingMac) {
            ip_addr sender_ip;
            sender_ip = ip_hdr.ip_src;
            icmps[sender_ip] = pair.second;
            break;
        }
    }

    AwaitingPacket pac = {packet, iface};

    // Check if a request for ip doesn't exist
    if(requests.find(ip) == requests.end()) {
        ArpRequest request = {ip, std::chrono::steady_clock::now(), 1, {}}; // leave last field blank because we push the packet back after the if statement
        requests[ip] = request;
        
        // Need to send initial ARP request here (send to broadcast MAC address ff-ff-ff-ff-ff-ff)
        // Grab the mac address (using getRoutingInterface) for the source mac address
        // Ask the next_hop ip address to figure out which MAC address to send to (this MAC address will be the destination address in the packet)
        RoutingInterface inter_face = routingTable->getRoutingInterface(iface);
        Packet arp_packet = createArpPacket(inter_face.ip, ip, inter_face.mac);
        arp_packets[ip] = arp_packet;
        interfaces[ip] = iface;
        packetSender->sendPacket(arp_packet, iface);
    }
    
    requests[ip].awaitingPackets.push_back(pac);
    return;
}


// the awaiting packets contain the IP addresses and interfaces in which the resolved MAC addresses should be sent to

// ip = next hop ip address, mac = resolved mac address using ARP
void ArpCache::sendQueuedPackets(uint32_t ip, mac_addr mac) {

    if (requests.find(ip) == requests.end()) {
        return;
    }
    ArpRequest arps = requests[ip]; // this contains the destion ip 
    /* This loop is supposed to perfrom the following functionality: 
        - Get the packet 
        - Modify the ethernet header of the packet and replace the source/dst mac addr
        - Send the new packet out
        - THIS ASSUMES THAT TTL AND CHECKSUM WERE HANDLED BY STATIC ROUTER
        - CHECK IF SENDPACKET ALREADY CHANGES THE MAC BASED ON INTERFACE ????????????????????????????
    */
    for (auto & currentP : arps.awaitingPackets) {
        Packet sending = currentP.packet;
        std::string interfaceName = currentP.iface;
        RoutingInterface interface = routingTable->getRoutingInterface(interfaceName);
        sr_ethernet_hdr_t ether_hdr;
        memcpy(&ether_hdr, sending.data(), sizeof(sr_ethernet_hdr_t));
        memcpy(ether_hdr.ether_dhost, mac.data(), ETHER_ADDR_LEN);
        memcpy(ether_hdr.ether_shost, interface.mac.data(), ETHER_ADDR_LEN);
        memcpy(sending.data(), &ether_hdr, sizeof(sr_ethernet_hdr_t));
        packetSender->sendPacket(sending,interfaceName);
    }
}

// Creates an ARP request packet
// source_ip, dest_ip passed in network form
Packet ArpCache::createArpPacket(ip_addr source_ip, ip_addr dest_ip, mac_addr sender_mac) {
    Packet pac;

    // Create ethernet header information at the front of the packet
    sr_ethernet_hdr_t eth_hdr;
    sr_ethernet_hdr_t * eth_hdr_ptr = &eth_hdr;
    uint8_t dhost[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC address
    uint16_t type = htons(sr_ethertype::ethertype_arp); // ARP protocol type
    
    memcpy(eth_hdr_ptr->ether_dhost, &dhost, ETHER_ADDR_LEN);
    memcpy(eth_hdr_ptr->ether_shost, sender_mac.data(), ETHER_ADDR_LEN);
    eth_hdr_ptr->ether_type = type;

    pac.resize(sizeof(sr_ethernet_hdr_t));
    memcpy(pac.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));
    
    // Create ARP header information inside the body of the packet
    sr_arp_hdr_t arp_hdr;
    sr_arp_hdr_t * arp_hdr_ptr = &arp_hdr;
    arp_hdr_ptr->ar_hrd = sr_arp_hrd_fmt::arp_hrd_ethernet; /* format of hardware address   */
    arp_hdr_ptr->ar_pro = sr_ethertype::ethertype_ip; /* protocol type (0x0800 for IPv4)*/
    arp_hdr_ptr->ar_hln = ETHER_ADDR_LEN; /* length of hardware address   */
    arp_hdr_ptr->ar_pln = sizeof(ip_addr); /* Length of ip address */
    arp_hdr_ptr->ar_op = htons(sr_arp_opcode::arp_op_request); /* ARP opcode */
    memcpy(arp_hdr_ptr->ar_sha, sender_mac.data(), ETHER_ADDR_LEN); /* sender hardware address */
    arp_hdr_ptr->ar_sip = source_ip; /* sender IP address */
    memcpy(arp_hdr_ptr->ar_tha, &dhost, ETHER_ADDR_LEN); /* target hardware address */
    arp_hdr_ptr->ar_tip = dest_ip; /* dest IP address */

    pac.resize(sizeof(sr_arp_hdr_t)); 
    memcpy(pac.data() + sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));

    return pac;
}

Packet ArpCache::createICMPPacket(const mac_addr dest_mac, const std::string& iface, const uint8_t type, const uint8_t code, Packet original_pac) {
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
// CHECK FOR CRC???
// Figure out which interface to exit on, and then use that interface's mac address as the source address

