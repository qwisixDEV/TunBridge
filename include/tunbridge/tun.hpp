#pragma once

#include "tunbridge/common.hpp"

void StopTunEngine();
DWORD WINAPI StartTunThread(LPVOID);
DWORD WINAPI DownloadTunThread(LPVOID);
