#pragma once

#include <string>

namespace tb {

// Sets and restores per-desktop system proxy settings. Never requires root.
class SystemProxy {
public:
    bool enable(int localPort, std::string* err);
    void disable();
    bool active() const { return changed_; }
    const std::string& desktop() const { return desktop_; }
    const std::string& hint() const { return hint_; }

private:
    std::string desktop_;
    std::string original_;
    std::string changedKey_;
    std::string hint_;
    bool changed_{false};
};

} // namespace tb
