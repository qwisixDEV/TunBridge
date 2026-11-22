#pragma once

#include "tunbridge/core.hpp"

#include <string>

namespace tb {

struct AppConfig {
    NetConfig net{};
    Mode mode{Mode::Proxy};
    bool minimizeToTray{true};
    bool autoRestoreZapret{false};
    bool autoStart{false};
};

std::string home_dir();
std::string config_home();
std::string data_home();
std::string runtime_dir();
std::string config_path();
std::string proxy_env_path();

bool load_app_config(AppConfig& out);
bool save_app_config(const AppConfig& in);
bool set_autostart(bool enabled, const CliOptions& flags, const std::string& executable);
bool is_autostart_enabled();

} // namespace tb
