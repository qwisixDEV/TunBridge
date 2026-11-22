#pragma once

#include "tunbridge/core.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace tb {

enum class HelperAction : std::int32_t {
    Ping = 0,
    StartTun = 1,
    StopTun = 2,
    StopZapret = 3,
    RestoreZapret = 4,
};

struct HelperRequest {
    HelperAction action{HelperAction::Ping};
    NetConfig net{};
    UpstreamProto proto{UpstreamProto::Socks5};
    std::string tunInterface{"tunbridge0"};
    std::string tunAddress{"10.251.251.1"};
    std::string tunPeer{"10.251.251.2"};
    std::string dnsServers{"1.1.1.1 8.8.8.8"};
    // Passed explicitly because pkexec resets most environment variables.
    std::string dataDir;
    std::string runtimeDir;
    bool stopZapret{false};
    bool restoreZapret{false};
};

struct HelperReply {
    bool ok{false};
    std::string message;
};

// Compact newline-delimited key=value protocol over a local Unix socket.
std::string encode_request(const HelperRequest& r);
bool decode_request(const std::string& text, HelperRequest& r);
std::string encode_reply(const HelperReply& r);
bool decode_reply(const std::string& text, HelperReply& r);

// GUI side: create a private listening socket, launch pkexec, exchange one
// request, and keep the connection alive as the helper watchdog channel.
class HelperClient {
public:
    HelperClient() = default;
    ~HelperClient();
    HelperClient(const HelperClient&) = delete;
    HelperClient& operator=(const HelperClient&) = delete;

    HelperReply launch(const HelperRequest& r, const std::string& helperPath,
                       std::string* err, int timeoutMs = 15000);
    void disconnect();
    bool connected() const { return fd_ >= 0; }

private:
    int listenFd_{-1};
    int fd_{-1};
    int helperPid_{-1};
    std::string socketPath_;
};

} // namespace tb
