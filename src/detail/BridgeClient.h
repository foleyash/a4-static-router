#ifndef BRIDGECLIENT_H
#define BRIDGECLIENT_H

#include <string>
#include <vector>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>

#include "PCAPDumper.h"
#include "RoutingTable.h"
#include "StaticRouter.h"
#include "router_bridge.pb.h"

class BridgeClient {
    using WSClient = websocketpp::client<websocketpp::config::asio_client>;

   public:
    BridgeClient(std::filesystem::path routingTablePath,
                 std::string pcapPrefix);

    void setInterfaces(const router_bridge::InterfaceUpdate& interfaces);

    void run();

   private:
    void onMessage(const std::string& message);

    std::shared_ptr<WSClient> client;

    std::shared_ptr<RoutingTable> routingTable;
    std::unique_ptr<StaticRouter> staticRouter;

    PcapDumper dumper;
};

#endif  // BRIDGECLIENT_H
