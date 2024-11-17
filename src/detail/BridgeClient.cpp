#include "BridgeClient.h"

#include <spdlog/spdlog.h>

#include <iostream>

#include "ArpCache.h"
#include "BridgeSender.h"
#include "utils.h"

// Constructor
BridgeClient::BridgeClient(std::filesystem::path routingTablePath,
                           std::string pcapPrefix)
    : dumper(pcapPrefix + "_input.pcap") {
    routingTable = std::make_shared<RoutingTable>(routingTablePath);

    client = std::make_shared<WSClient>();
    client->init_asio();
    client->clear_access_channels(websocketpp::log::alevel::all);
    client->clear_error_channels(websocketpp::log::elevel::all);

    // Set handlers before creating the connection
    client->set_message_handler([this](auto hdl, WSClient::message_ptr msg) {
        onMessage(msg->get_payload());
    });

    client->set_fail_handler([this](auto hdl) {
        spdlog::error("Connection failed (is POX running?)");
    });

    std::string wsUri = "ws://localhost:8080";
    websocketpp::lib::error_code ec;
    WSClient::connection_ptr con = client->get_connection(wsUri, ec);
    if (ec) {
        std::cout << "could not create connection because: " << ec.message()
                  << std::endl;
        throw std::runtime_error("Could not create connection");
    }

    auto bridgeSender = std::make_shared<BridgeSender>(client, con, pcapPrefix);
    auto arpCache = std::make_unique<ArpCache>(std::chrono::seconds(15),
                                               bridgeSender, routingTable);
    staticRouter = std::make_unique<StaticRouter>(std::move(arpCache),
                                                  routingTable, bridgeSender);

    client->connect(con);
}

// Method to request interfaces
void BridgeClient::setInterfaces(
    const router_bridge::InterfaceUpdate& interfaces) {
    for (const auto& iface : interfaces.interfaces()) {
        mac_addr mac;
        std::copy(iface.mac().begin(), iface.mac().begin() + mac.size(),
                  mac.begin());
        routingTable->setRoutingInterface(iface.name(), mac, iface.ip());
    }

    spdlog::info("Set interfaces, router ready to route things!");
}

void BridgeClient::onMessage(const std::string& message) {
    router_bridge::ProtocolMessage protoMessage;
    protoMessage.ParseFromString(message);

    if (protoMessage.has_router_packet()) {
        auto& packetMessage = protoMessage.router_packet();
        std::vector<uint8_t> packet(packetMessage.data().begin(),
                                    packetMessage.data().end());
        dumper.dump(packet);

        staticRouter->handlePacket(packet, packetMessage.interface());
    } else if (protoMessage.has_interface_update()) {
        setInterfaces(protoMessage.interface_update());
    }
}

void BridgeClient::run() { client->run(); }
