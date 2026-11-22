#pragma once

// Shared data model (NetConfig, ProbeResult, CLI parsing) is platform-neutral.
#include "tunbridge/core.hpp"

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <gdiplus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif

// Контролы и сообщения
#define ID_BTN_TRAY_WIN    190
#define ID_BTN_SETTINGS    191
#define ID_BTN_BACK        192
#define ID_EDIT_IP         101
#define ID_EDIT_SPORT      102
#define ID_EDIT_USER       103
#define ID_EDIT_PASS       104
#define ID_EDIT_LPORT      105
#define ID_BTN_MODE_PROXY  200
#define ID_BTN_MODE_TUN    201
#define ID_BTN_SCAN        202
#define ID_BTN_TEST        203
#define ID_BTN_SHOWPASS    204
#define ID_BTN_TOGGLE      205
#define ID_BTN_TRAY_OPT    206
#define ID_BTN_DL_TUN      207
#define ID_BTN_STOP_ZAPRET 208
#define ID_BTN_AUTOSTART   209
#define ID_BTN_AUTO_ZAPRET 210
#define ID_TRAY_SHOW       301
#define ID_TRAY_TOGGLE     302
#define ID_TRAY_EXIT       303

#define TIMER_STATS        1
#define WM_APP_TRAY        (WM_APP + 1)
#define WM_APP_SCAN_DONE   (WM_APP + 2)
#define WM_APP_PROBE_DONE  (WM_APP + 3)
#define WM_APP_TUN_DONE    (WM_APP + 4)
#define WM_APP_DL_DONE     (WM_APP + 5)
#define WM_APP_AUTOSTART   (WM_APP + 6)
#define WM_APP_AUTODL      (WM_APP + 7)

// Реестр, окно и сторонние компоненты
inline constexpr const wchar_t* REG_WIN_INET  = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
inline constexpr const wchar_t* REG_WIN_RUN   = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
inline constexpr const wchar_t* REG_APP_CFG   = L"Software\\TunBridge";
inline constexpr const wchar_t* RUN_VAL_NAME  = L"TunBridge";
inline constexpr const wchar_t* APP_WND_CLASS = L"TunBridgeWin11";
inline constexpr const char* WINTUN_DLL_SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

// Палитра Windows 11
inline constexpr COLORREF COL_BG = RGB(28,28,28), COL_SURFACE = RGB(38,38,38), COL_SURFACE_RO = RGB(33,33,33);
inline constexpr COLORREF COL_SURFACE_HV = RGB(48,48,48), COL_SURFACE_PR = RGB(58,58,58), COL_SEG_ACTIVE = RGB(54,54,54);
inline constexpr COLORREF COL_BORDER = RGB(51,51,51), COL_BORDER_FOC = RGB(96,96,96), COL_TEXT = RGB(243,243,243);
inline constexpr COLORREF COL_ICON_IDLE = RGB(214,214,214), COL_TEXT_RO = RGB(178,178,178), COL_MUTED = RGB(154,154,154);
inline constexpr COLORREF COL_ACCENT = RGB(16,185,129), COL_ACCENT_HV = RGB(20,200,140), COL_ACCENT_PR = RGB(14,159,110);
inline constexpr COLORREF COL_DANGER = RGB(217,72,72), COL_DANGER_HV = RGB(226,91,91), COL_DANGER_PR = RGB(191,59,59);

// Общее состояние приложения
extern float g_scale;

// Шрифты, кисти, контролы
extern HFONT g_fontTitle, g_fontBody, g_fontSemi, g_fontSeg, g_fontSegSemi, g_fontSmall, g_fontMono, g_fontIcon;
extern wchar_t g_uiFontName[64], g_monoFontName[64], g_iconFontName[64];
extern wchar_t g_glyphEyeOff, g_glyphStop;
extern HBRUSH g_brInput, g_brInputRo;

extern HWND g_hwnd, g_tooltip;
extern HWND hBtnTrayWin, hBtnSettings, hBtnBack, hBtnModeProxy, hBtnModeTun, hEditIp, hBtnScan, hBtnTest, hBtnToggle;
extern HWND hEditSPort, hEditLPort, hEditUser, hEditPass, hBtnShowPass;
extern HWND hBtnTrayOpt, hBtnAutoStart, hBtnAutoZapret, hBtnDlTun, hBtnStopZapret;
extern WNDPROC g_origBtnProc;
extern int g_focusedEditId, g_screen;

extern HICON g_appIconBig, g_appIconSmall, g_trayIconOn, g_trayIconOff;
extern NOTIFYICONDATAW g_nid;
extern bool g_trayAdded, g_passVisible, g_autoStart, g_zapretActive, g_hasError;
extern wchar_t g_passChar, g_ipLabelText[48], g_errMsg[192];
extern int g_minimizeToTray, g_autoRestoreZapret, g_testIconState, g_ipLabelState, g_pingMs, g_mode;
extern char g_countryCode[8];

extern volatile LONG g_upstreamProto, g_connGen, g_running, g_busy, g_scanning, g_testing;
extern volatile LONG g_activeConns, g_workerThreads, g_shuttingDown;
extern volatile LONG64 g_bytesTotal;

extern SOCKET g_listenSock;
extern HANDLE g_serverThread, g_tunProc, g_tunJob, g_tunLogThread;
extern wchar_t g_exeDir[MAX_PATH], g_exePath[MAX_PATH];
extern DWORD g_tunIfIndex, g_prevTunOctets;
extern bool g_hasPrevOctets;
extern char g_addedPhoneRouteIp[64], g_tunLastErr[512];

// Автовозврат Zapret
extern wchar_t g_stoppedZapretSvc[64], g_stoppedZapretExe[MAX_PATH], g_stoppedZapretWorkDir[MAX_PATH];
extern wchar_t g_stoppedZapretCmdLine[8192];

extern CRITICAL_SECTION g_logCs, g_cfgCs;

// Preserve the original global names used by the Win32 UI code.
using NetConfig = tb::NetConfig;
extern NetConfig g_cfg;

using ProbeResult = tb::ProbeResult;

inline int S(int v) { return (int)(v * g_scale + 0.5f); }
inline Gdiplus::Color GCol(COLORREF c, BYTE a = 255) { return Gdiplus::Color(a, GetRValue(c), GetGValue(c), GetBValue(c)); }

// --- Безопасные хелперы ---
void SafeCopyA(char* d, size_t n, const char* s);
void SafeCopyW(wchar_t* d, size_t n, const wchar_t* s);
bool IsSafeHostString(const char* s);
bool ComputeFileSha256Hex(const wchar_t* path, char outHex[65]);
PIP_ADAPTER_ADDRESSES AllocAdapters();
