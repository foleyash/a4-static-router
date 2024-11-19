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
            // log something and drop request???
            // what do we do with queued packets for this ARP request???
            it = requests.erase(it);
        }
        
        else if (now - current_request.lastSent >= timeout) {
            // Resend packet 
            
        }
        else {
            continue;
        }
    }

    // TODO: Your code should end here

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

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    auto entry = entries.find(ip);
    if (entry != entries.end()) {
        return entry->second.mac;
    }

    // Need to send initial ARP request here (send to broadcast MAC address ff-ff-ff-ff-ff-ff)

    return std::nullopt; // Return nothing if no entry for this ip exists
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    AwaitingPacket pac = {packet, iface};

    // Check if a request for ip doesn't exist
    if(requests.find(ip) == requests.end()) {
        ArpRequest request = {ip,std::chrono::steady_clock::now(), 0, {pac}};
        requests[ip] = request;
    }
    else {
        requests[ip].awaitingPackets.push_back(pac);
    }
    return;
}


// the awaiting packets contain the IP addresses and interfaces in which the resolved MAC addresses should be sent to