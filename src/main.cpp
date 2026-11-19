#include "tunbridge/app.hpp"
#include "tunbridge/config.hpp"
#include "tunbridge/system.hpp"
#include "tunbridge/ui.hpp"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR lpCmd, int nCmdShow) {
    bool isStopZap   = lpCmd && strstr(lpCmd, "--stop-zapret") != nullptr;
    bool isAutoTun   = lpCmd && strstr(lpCmd, "--autostart-tun") != nullptr;
    bool isAutoDl    = lpCmd && strstr(lpCmd, "--download-tun") != nullptr;
    bool isMinimized = lpCmd && strstr(lpCmd, "--minimized") != nullptr;

    if (isStopZap) { StopZapret(); return 0; }
    if (!isAutoTun && !isAutoDl) {
        HWND ex = FindWindowW(APP_WND_CLASS, nullptr);
        if (ex) { ShowWindow(ex, SW_SHOW); ShowWindow(ex, SW_RESTORE); SetForegroundWindow(ex); return 0; }
    } else Sleep(250);

    EnableDpiAwareness(); g_scale = QuerySystemScale();
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES }; InitCommonControlsEx(&icc);
    InitializeCriticalSection(&g_logCs); InitializeCriticalSection(&g_cfgCs);

    Gdiplus::GdiplusStartupInput gi; ULONG_PTR gTok = 0; Gdiplus::GdiplusStartup(&gTok, &gi, nullptr);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    InitExePaths(); LoadConfig(); CleanupStaleStateOnStartup();
    g_appIconBig = MakeAppIcon(32, true); g_appIconSmall = MakeAppIcon(16, true);
    g_trayIconOn = MakeAppIcon(16, true); g_trayIconOff  = MakeAppIcon(16, false);

    WNDCLASSEXW wc = { sizeof(wc), 0, WndProc, 0, 0, hInst, g_appIconBig, LoadCursor(nullptr, IDC_ARROW), nullptr, nullptr, APP_WND_CLASS, g_appIconSmall };
    RegisterClassExW(&wc);

    DWORD st = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
    RECT rc = { 0, 0, S(360), S(400) }; AdjustWindowRectEx(&rc, st, FALSE, 0);
    HWND hwnd = CreateWindowExW(0, APP_WND_CLASS, L"TunBridge", st, CW_USEDEFAULT, CW_USEDEFAULT,
                                rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInst, nullptr);
    if (hwnd) {
        if (isMinimized) ShowWindow(hwnd, g_trayAdded ? SW_HIDE : SW_SHOWMINNOACTIVE);
        else { ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd); }

        if (isAutoTun) { g_mode = 1; RefreshControls(); PostMessageW(hwnd, WM_APP_AUTOSTART, 0, 0); }
        else if (isAutoDl) { PostMessageW(hwnd, WM_APP_AUTODL, 0, 0); }

        MSG m;
        while (GetMessageW(&m, nullptr, 0, 0)) {
            if (!IsDialogMessageW(hwnd, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
        }
    }

    InterlockedExchange(&g_shuttingDown, 1);
    for (int i = 0; i < 40 && InterlockedCompareExchange(&g_workerThreads, 0, 0) > 0; i++) Sleep(50);
    WSACleanup();
    Gdiplus::GdiplusShutdown(gTok);
    if (InterlockedCompareExchange(&g_workerThreads, 0, 0) == 0) {
        DeleteCriticalSection(&g_logCs); DeleteCriticalSection(&g_cfgCs);
    }
    return 0;
}
