#pragma once

#include "tunbridge/common.hpp"

DWORD WINAPI ScanThread(LPVOID param);
void LaunchProbeAsync(bool fromBtn);
