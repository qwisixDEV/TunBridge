#pragma once

// Linux helper-only API. Every privileged operation is registered in an
// RAII state object so that a disconnect/signal can undo it in reverse order.
// This header is intentionally not included by GUI translation units.

#include "tunbridge/helper_protocol.hpp"

#include <memory>
#include <string>
#include <vector>

namespace tb {

struct PrivilegedStateImpl;

class PrivilegedState {
public:
    PrivilegedState();
    ~PrivilegedState();

    PrivilegedState(const PrivilegedState&) = delete;
    PrivilegedState& operator=(const PrivilegedState&) = delete;
    PrivilegedState(PrivilegedState&&) = delete;
    PrivilegedState& operator=(PrivilegedState&&) = delete;

    // Creates tunbridge0, configures it, installs the routes/DNS and starts
    // tun2socks. On any failure everything applied so far is rolled back.
    bool start_tun(const HelperRequest& req, std::string* err);

    // On-line cleanup used for an explicit StopTun request. If this process
    // owns an active state it is rolled back; otherwise a best-effort global
    // cleanup is performed.
    bool stop_tun(std::string* err);

    // Stops systemd units named zapret* and nfqws/tpws processes. Stopped unit
    // names are remembered in the state (and in a private runtime file) so a
    // later RestoreZapret request can start them again.
    bool stop_zapret(std::string* err);
    bool restore_zapret(std::string* err);
    bool zapret_active(std::string* detail) const;

    // Undo every recorded change in reverse order. Idempotent.
    void rollback();

    // Forget recorded changes without undoing them (intentional stop).
    void commit();

    bool has_changes() const;

private:
    std::unique_ptr<PrivilegedStateImpl> impl_;
};

// helpers used by helper_main.cpp
bool privileged_is_root();
std::string privileged_runtime_dir();

// pkexec clears XDG_RUNTIME_DIR; the GUI passes it in the request so DNS
// backups can be persisted and restored by a fresh helper process.
bool set_privileged_runtime_dir(const std::string& path);

} // namespace tb
