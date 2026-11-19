#include "tunbridge/common.hpp"

float g_scale = 1.0f;

// Шрифты, кисти, контролы
HFONT g_fontTitle, g_fontBody, g_fontSemi, g_fontSeg, g_fontSegSemi, g_fontSmall, g_fontMono, g_fontIcon;
wchar_t g_uiFontName[64] = L"Segoe UI", g_monoFontName[64] = L"Consolas", g_iconFontName[64] = L"Segoe MDL2 Assets";
wchar_t g_glyphEyeOff = 0xE7B3, g_glyphStop = 0xE71A;
HBRUSH g_brInput, g_brInputRo;

HWND g_hwnd, g_tooltip;
HWND hBtnTrayWin, hBtnSettings, hBtnBack, hBtnModeProxy, hBtnModeTun, hEditIp, hBtnScan, hBtnTest, hBtnToggle;
HWND hEditSPort, hEditLPort, hEditUser, hEditPass, hBtnShowPass;
HWND hBtnTrayOpt, hBtnAutoStart, hBtnAutoZapret, hBtnDlTun, hBtnStopZapret;
WNDPROC g_origBtnProc;
int g_focusedEditId = 0, g_screen = 0;

HICON g_appIconBig, g_appIconSmall, g_trayIconOn, g_trayIconOff;
NOTIFYICONDATAW g_nid = {};
bool g_trayAdded = false, g_passVisible = false, g_autoStart = false, g_zapretActive = false, g_hasError = false;
wchar_t g_passChar = L'*', g_ipLabelText[48] = L"", g_errMsg[192] = L"";
int g_minimizeToTray = 1, g_autoRestoreZapret = 0, g_testIconState = 0, g_ipLabelState = 0, g_pingMs = -1, g_mode = 0;
char g_countryCode[8] = {};

volatile LONG g_upstreamProto = 0, g_connGen = 0, g_running = 0, g_busy = 0, g_scanning = 0, g_testing = 0;
volatile LONG g_activeConns = 0, g_workerThreads = 0, g_shuttingDown = 0;
volatile LONG64 g_bytesTotal = 0;

SOCKET g_listenSock = INVALID_SOCKET;
HANDLE g_serverThread, g_tunProc, g_tunJob, g_tunLogThread;
wchar_t g_exeDir[MAX_PATH], g_exePath[MAX_PATH];
DWORD g_tunIfIndex = 0, g_prevTunOctets = 0;
bool g_hasPrevOctets = false;
char g_addedPhoneRouteIp[64] = {}, g_tunLastErr[512] = {};

// Автовозврат Zapret
wchar_t g_stoppedZapretSvc[64] = {}, g_stoppedZapretExe[MAX_PATH] = {}, g_stoppedZapretWorkDir[MAX_PATH] = {};
wchar_t g_stoppedZapretCmdLine[8192] = {};

CRITICAL_SECTION g_logCs, g_cfgCs;

NetConfig g_cfg = { "192.168.1.66", 10808, "incy_99d625cb", "7038a5a40b5dd855102e72f804531bcc", 8888 };
