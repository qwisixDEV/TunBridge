#pragma once

#include "tunbridge/core.hpp"

#include <cstdint>
#include <string>

namespace tb {

struct UpstreamResult {
    int fd{-1};
    UpstreamProto proto{UpstreamProto::Socks5};
    NetEngineError err{NetEngineError::Ok};
};

// Blocking helper used by the LAN scanner / connectivity test only.
UpstreamResult connect_upstream_blocking(const NetConfig& cfg, const std::string& host,
                                         std::uint16_t port, int timeoutMs,
                                         UpstreamProto preferred = UpstreamProto::Auto);

// Error code compatible with the original TestUpstreamAuthAndProto():
// 0 ok, 1 unreachable, 2 not a proxy, 3 bad credentials.
int test_upstream(const NetConfig& cfg, UpstreamProto* detected, int timeoutMs);

} // namespace tb
