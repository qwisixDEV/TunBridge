#pragma once

#include "tunbridge/core.hpp"

#include <string>

namespace tb {

struct HealthResult {
    int err{0};
    int pingMs{-1};
    UpstreamProto proto{UpstreamProto::Socks5};
    std::string country;
};

// Mirrors the original cp.cloudflare.com /generate_204 + /cdn-cgi/trace and
// ip-api.com fallback logic. Runs on a GUI-owned worker thread.
HealthResult probe_health(const NetConfig& cfg, int timeoutMs = 5000);

} // namespace tb
