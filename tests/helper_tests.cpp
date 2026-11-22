// Protocol round-trip checks for the GUI <-> privileged helper channel.
#include <tunbridge/helper_protocol.hpp>

#include <cstdio>
#include <iostream>
#include <string>

namespace {

int g_failures = 0;

#define CHECK(cond, name)                                                        \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_failures;                                                        \
            std::cout << "[FAIL] " << name << " (line " << __LINE__ << ")\n";    \
        } else {                                                                  \
            std::cout << "[PASS] " << name << '\n';                              \
        }                                                                        \
    } while (false)

} // namespace

int main() {
    tb::HelperRequest req;
    req.action = tb::HelperAction::StartTun;
    std::snprintf(req.net.ip, sizeof(req.net.ip), "10.0.0.1");
    req.net.socksPort = 1080;
    std::snprintf(req.net.user, sizeof(req.net.user), "user\\name");
    std::snprintf(req.net.pass, sizeof(req.net.pass), "line1\nline2");
    req.net.localPort = 8888;
    req.proto = tb::UpstreamProto::HttpConnect;
    req.tunInterface = "tunbridge0";
    req.dataDir = "/home/user/.local/share";
    req.runtimeDir = "/run/user/1000";
    req.stopZapret = true;

    const std::string encoded = tb::encode_request(req);
    CHECK(encoded.find("user=user\\\\name\n") != std::string::npos,
          "request escapes backslashes");
    CHECK(encoded.find("pass=line1\\nline2\n") != std::string::npos,
          "request escapes newlines");

    tb::HelperRequest decoded;
    CHECK(tb::decode_request(encoded, decoded), "request frame decodes");
    CHECK(decoded.action == req.action && decoded.proto == req.proto &&
              std::string(decoded.net.ip) == "10.0.0.1" &&
              decoded.net.socksPort == 1080 && decoded.net.localPort == 8888 &&
              decoded.dataDir == "/home/user/.local/share" &&
              decoded.runtimeDir == "/run/user/1000" &&
              decoded.stopZapret && !decoded.restoreZapret,
          "request fields survive the round trip");
    CHECK(std::string(decoded.net.user) == "user\\name" &&
              std::string(decoded.net.pass) == "line1\nline2",
          "escaped credentials decode exactly");

    tb::HelperReply reply;
    reply.ok = true;
    reply.message = "TUN запущен\nстрока 2";
    const std::string replyText = tb::encode_reply(reply);
    tb::HelperReply decodedReply;
    CHECK(tb::decode_reply(replyText, decodedReply) && decodedReply.ok &&
              decodedReply.message == reply.message,
          "reply frame round trip");
    CHECK(!tb::decode_reply("garbage\n\n", decodedReply),
          "malformed reply is rejected");

    std::cout << "Results: " << (g_failures == 0 ? "all checks passed" : "failures") << '\n';
    return g_failures == 0 ? 0 : 1;
}
