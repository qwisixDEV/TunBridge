#pragma once

#include "tunbridge/common.hpp"

void GetNetConfig(NetConfig* out);
void SaveConfig();
void LoadConfig();
void SetWindowsProxy(bool enable, int localPort);
bool IsAutoStartEnabled();
bool SetAutoStartEnabled(bool on);
