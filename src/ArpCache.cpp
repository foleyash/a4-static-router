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
        if (current_request.timesSent >= 7) {
            // send ICMP message and use the PACKED attribute
            it = requests.erase(it); // (will also get rid of queued packets for this request)
        }
        else if (now - current_request.lastSent >= std::chrono::seconds(1)) {
            // Resend packet 
            ip_addr ip = current_request.ip;
            std::string iface = interfaces[ip];
            Packet pac = arp_packets[ip];
            packetSender->sendPacket(pac, iface);
            it->second.timesSent++;
        }
        else {
            continue;
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

// Input: ip is the next hop ip address
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

// Creates an ARP request packet
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
    arp_hdr_ptr->ar_sip = htonl(source_ip); /* sender IP address */
    memcpy(arp_hdr_ptr->ar_tha, &dhost, ETHER_ADDR_LEN); /* target hardware address */
    arp_hdr_ptr->ar_tip = htonl(dest_ip); /* dest IP address */

    pac.resize(sizeof(sr_ethernet_hdr_t));
    memcpy(pac.data() + sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));

    return pac;
}

// CHECK FOR CRC???
// Figure out which interface to exit on, and then use that interface's mac address as the source address

