#include "BridgeSender.h"

BridgeSender::BridgeSender(std::shared_ptr<WSClient> client,
                           WSClient::connection_ptr connection,
                           std::string pcapPrefix)
    : client(std::move(client)),
      connection(std::move(connection)),
      dumper(pcapPrefix + "_output.pcap") {}

void BridgeSender::sendPacket(Packet packet, const std::string& iface) {
    router_bridge::ProtocolMessage message;
    RouterPacket& routerPacket = *message.mutable_router_packet();

    routerPacket.set_interface(iface);
    routerPacket.set_data(packet.data(), packet.size());

    dumper.dump(packet);
    send(message);
}

void BridgeSender::send(const router_bridge::ProtocolMessage& message) {
    client->send(connection, message.SerializeAsString(),
                 websocketpp::frame::opcode::binary);
}
