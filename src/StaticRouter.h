#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:

    Packet createICMPPacket(const mac_addr dest_mac, const std::string iface, const uint8_t type, const uint8_t code, Packet original_pac);

    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<IArpCache> arpCache;\


    /* Structure of a type11 ICMP header
    */
    struct sr_icmp_t11_hdr {
        uint8_t icmp_type;
        uint8_t icmp_code;
        uint16_t icmp_sum;
        uint16_t unused;
        uint8_t data[ICMP_DATA_SIZE];

    } __attribute__ ((packed)) ;
    typedef struct sr_icmp_t11_hdr sr_icmp_t11_hdr_t;
};


#endif //STATICROUTER_H
