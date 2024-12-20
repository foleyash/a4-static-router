#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <vector>
#include <array>
#include <chrono>
#include <set>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <atomic> // ADDED THIS IN 

#include "IArpCache.h"
#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"
#include "RoutingTable.h"

class ArpCache : public IArpCache {
public:
    ArpCache(std::chrono::milliseconds timeout,
        std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache() override;

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac) override;

    std::optional<mac_addr> getEntry(uint32_t ip) override;

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) override;
   

private:
    void loop();

    void sendQueuedPackets(uint32_t ip, mac_addr mac);
    Packet createArpPacket(ip_addr sip, ip_addr dip, mac_addr mac);
    Packet createICMPPacket(const mac_addr dest_mac, const std::string iface, const uint8_t type, const uint8_t code, Packet original_pac);

    std::optional<mac_addr> tickGetEntry(uint32_t ip);

    std::chrono::milliseconds timeout;

    std::mutex mutex;
    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
    std::unordered_map<ip_addr, ArpRequest> requests;

    // Stores the iface for the next hop Ip addr 
    std::unordered_map<ip_addr, std::string> interfaces;
    // Stores the Packet that will be resent as a ARP REQUEST
    std::unordered_map<ip_addr, Packet> arp_packets;
    

    // This map is used for the ICMP MESSAGE. Change this to have whatever functionality we need
    std::unordered_map<ip_addr, RoutingInterface> icmps; // Maybe need to look at key (could we use source IP of each packet?)

    /* Structure of a type11 ICMP header
    */
    struct sr_icmp_t11_hdr {
        uint8_t icmp_type;
        uint8_t icmp_code;
        uint16_t icmp_sum;
        uint32_t unused;
        uint8_t data[ICMP_DATA_SIZE];

    } __attribute__ ((packed)) ;
    typedef struct sr_icmp_t11_hdr sr_icmp_t11_hdr_t;
};



#endif //ARPCACHE_H
