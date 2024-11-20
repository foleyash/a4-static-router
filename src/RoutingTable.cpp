#include "RoutingTable.h"

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    if (!std::filesystem::exists(routingTablePath)) {
        throw std::runtime_error("Routing table file does not exist");
    }

    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open routing table file");
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }
        
        std::istringstream iss(line);
        std::string dest, gateway, mask, iface;
        iss >> dest >> gateway >> mask >> iface;

        uint32_t dest_ip, gateway_ip, subnet_mask;

        if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
            inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
            inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
            }

        routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
    }
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {   
    RoutingEntry best_match;
    
    int max_match_len = -1;
    // this will give us the minimum prefix length
    for (auto& entry : routingEntries) {
        ip_addr tmp_ip = ip;
        ip_addr cmp_ip = entry.dest;
        ip_addr tmp_mask = entry.mask;
        uint32_t network_bit_len = 0; // This gives us the number of bits for the actual network
        const uint32_t MAX_NETWORK_BIT_LEN = 32;
        for(int i = 0; i < MAX_NETWORK_BIT_LEN; i++) {
            int isOne = tmp_mask & 0b1; // If lsb is 0 --> return 0, lsb is 1 --> return 1
            if (isOne) {
                network_bit_len = 32 - i;
                break;
            }
            tmp_mask >>= 1;
        }

        // 255.255.0.0  , target ip is - (192.168.0.37)
        // 192.167.0.37     netmask 255.0.0.0
        // 192.168.0.35     netmask 255.255.0.0
        // 192.168.2.59     netmask 255.255.0.0

        uint32_t target = cmp_ip & entry.mask; // Not sure if this is needed
        uint32_t tmp = tmp_ip & entry.mask;
        if (target == tmp) {
            // Update maxPrefix if longer
            if (network_bit_len > max_match_len) {
                max_match_len = network_bit_len;
                best_match = entry;
            }
        }
    }
    // Look at network mask bit length (this tells how specific we need to be)
    // (16) - Prefix (16 bits) is a direct match with our ip (16 bits) (IDEAL MATCH)
    return best_match; 
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}

// We have a routing table
// In the routing table, there are next_hop IPs and interfaces (0, 1, 2)
// 0 , mac, ip 
// Each interface will correspond to a next_hop IP, and that next_hop IP will correspond to a next_hop MAC address
// 0, 1, 2, 3, 4, 5