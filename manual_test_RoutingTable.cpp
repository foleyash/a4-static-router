#include <iostream>
#include <cassert>
#include "RoutingTable.h"
// #define __BYTE_ORDER __LITTLE_ENDIAN
// Helper function to create a RoutingEntry
RoutingEntry makeRoutingEntry(uint32_t dest, uint32_t gateway, uint32_t mask, const std::string& iface) {
    RoutingEntry entry;
    entry.dest = dest;
    entry.gateway = gateway;
    entry.mask = mask;
    entry.iface = iface;
    return entry;
}

void testExactMatch() {
    RoutingTable routingTable("");

    // Populate routing table
    routingTable.routingEntries.push_back(makeRoutingEntry(0xC0A80000, 0x01010101, 0xFFFF0000, "eth0")); // 192.168.0.0/16
    routingTable.routingEntries.push_back(makeRoutingEntry(0xC0A80100, 0x01010102, 0xFFFFFF00, "eth1")); // 192.168.1.0/24

    ip_addr testIP = 0xC0A80101; // 192.168.1.1
    auto result = routingTable.getRoutingEntry(testIP);

    assert(result.has_value());
    assert(result->dest == 0xC0A80100);   // Expect 192.168.1.0/24
    assert(result->mask == 0xFFFFFF00);  // Expect /24 mask
    assert(result->gateway == 0x01010102); // Gateway 1.1.1.2
    assert(result->iface == "eth1");      // Interface eth1

    std::cout << "testExactMatch passed!" << std::endl;
}

void testLongestPrefixMatch() {
    RoutingTable routingTable("");

    // Populate routing table
    routingTable.routingEntries.push_back(makeRoutingEntry(0xC0A80000, 0x01010101, 0xFFFF0000, "eth0")); // 192.168.0.0/16
    routingTable.routingEntries.push_back(makeRoutingEntry(0xC0A80100, 0x01010102, 0xFFFFFF00, "eth1")); // 192.168.1.0/24

    ip_addr testIP = 0xC0A80001; // 192.168.0.1
    auto result = routingTable.getRoutingEntry(testIP);

    assert(result.has_value());
    assert(result->dest == 0xC0A80000);   // Expect 192.168.0.0/16
    assert(result->mask == 0xFFFF0000);  // Expect /16 mask
    assert(result->gateway == 0x01010101); // Gateway 1.1.1.1
    assert(result->iface == "eth0");      // Interface eth0

    std::cout << "testLongestPrefixMatch passed!" << std::endl;
}

void testNoMatch() {
    RoutingTable routingTable("");

    // Populate routing table
    routingTable.routingEntries.push_back(makeRoutingEntry(0xC0A80000, 0x01010101, 0xFFFF0000, "eth0")); // 192.168.0.0/16

    ip_addr testIP = 0x01010101; // 1.1.1.1
    auto result = routingTable.getRoutingEntry(testIP);

    assert(!result.has_value()); // Expect no match

    std::cout << "testNoMatch passed!" << std::endl;
}

int main() {
    try {
        testExactMatch();
        testLongestPrefixMatch();
        testNoMatch();
    } catch (const std::exception& e) {
        std::cerr << "A test failed: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "All tests passed!" << std::endl;
    return 0;
}
