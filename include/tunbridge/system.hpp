#pragma once

#include "tunbridge/common.hpp"

void EnableDpiAwareness();
float QuerySystemScale();
void InitExePaths();
bool IsElevated();
bool FindTunBinaries(wchar_t* outExe, wchar_t* outDll);
DWORD RunHiddenWait(const wchar_t* cmd, DWORD ms);
bool IsZapretActive();
void ClearSavedZapretState();
void CaptureZapretStateBeforeStop();
void StopZapret();
void RestoreZapretIfNeeded();
void CleanupOrphanedTunProcesses();
void SaveLastPhoneRouteIp(const char* ip);
void CleanupSavedPhoneRouteFromReg();
void CleanupStaleStateOnStartup();
