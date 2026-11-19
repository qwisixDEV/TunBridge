#include "tunbridge/app.hpp"
#include "tunbridge/config.hpp"
#include "tunbridge/net.hpp"
#include "tunbridge/probe.hpp"
#include "tunbridge/system.hpp"
#include "tunbridge/tun.hpp"
#include "tunbridge/ui.hpp"

// --- Управление экранами и режимами ---
static bool CanWriteToExeDir() {
    wchar_t p[MAX_PATH + 32]; _snwprintf(p, MAX_PATH + 31, L"%s\\_tunbridge_wr.tmp", g_exeDir); p[MAX_PATH + 31] = 0;
    HANDLE h = CreateFileW(p, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h); return true;
}

void StartDownloadTun(HWND hwnd) {
    if (!CanWriteToExeDir()) {
        if (!IsElevated()) {
            if (MessageBoxW(hwnd, L"Нет прав записи в папку программы (например, Program Files).\n\nПерезапустить от имени администратора для загрузки драйвера TUN?",
                            L"Права доступа", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
                ShellExecuteW(hwnd, L"runas", g_exePath, L"--download-tun", g_exeDir, SW_SHOWNORMAL);
                SendMessageW(hwnd, WM_CLOSE, 0, 0);
            }
        } else SetErrorMsg(L"Ошибка · Нет прав записи в папку");
        return;
    }
    if (!g_running && !g_busy && InterlockedCompareExchange(&g_busy, 1, 0) == 0) {
        SetErrorMsg(nullptr); RefreshControls();
        HANDLE ht = CreateThread(nullptr, 0, DownloadTunThread, nullptr, 0, nullptr);
        if (ht) CloseHandle(ht); else InterlockedExchange(&g_busy, 0);
    }
}
void SwitchScreen(int scr) {
    if (g_screen == scr) return;
    if (g_screen == 1) SaveConfig();
    g_screen = scr; g_focusedEditId = 0;
    if (g_screen == 1) { g_zapretActive = IsZapretActive(); g_autoStart = IsAutoStartEnabled(); }
    int sm = g_screen == 0 ? SW_SHOW : SW_HIDE, ss = g_screen == 1 ? SW_SHOW : SW_HIDE;
    HWND mc[] = { hBtnTrayWin, hBtnSettings, hBtnModeProxy, hBtnModeTun, hEditIp, hBtnScan, hBtnTest, hBtnToggle };
    HWND sc[] = { hBtnBack, hEditSPort, hEditLPort, hEditUser, hEditPass, hBtnShowPass, hBtnTrayOpt, hBtnAutoStart, hBtnAutoZapret, hBtnDlTun, hBtnStopZapret };
    for (HWND h : mc) ShowWindow(h, sm);
    for (HWND h : sc) ShowWindow(h, ss);
    if (g_hwnd) ResizeWindowClient(g_hwnd, 360, g_screen == 1 ? 468 : 400);
    RefreshControls(); InvalidateRect(g_hwnd, nullptr, FALSE);
}
void RefreshControls() {
    bool on = g_running != 0, busy = g_busy != 0, lock = on || busy;
    EnableWindow(hBtnModeProxy, !lock); EnableWindow(hBtnModeTun, !lock);
    EnableWindow(hBtnScan, !lock && !g_scanning); EnableWindow(hBtnTest, !busy && !g_testing);
    EnableWindow(hBtnToggle, !busy); EnableWindow(hBtnDlTun, !lock);
    EnableWindow(hBtnStopZapret, !busy && g_zapretActive);
    HWND edits[] = { hEditIp, hEditSPort, hEditLPort, hEditUser, hEditPass };
    for (HWND e : edits) { SendMessageW(e, EM_SETREADONLY, lock ? TRUE : FALSE, 0); InvalidateRect(e, nullptr, TRUE); }
    SetWindowTextW(hBtnToggle, busy ? L"Подождите..." : (on ? L"Отключить" : L"Подключить"));
    InvalidateRect(hBtnAutoStart, nullptr, FALSE); InvalidateRect(hBtnAutoZapret, nullptr, FALSE);
    InvalidateRect(hBtnStopZapret, nullptr, FALSE); InvalidateRect(g_hwnd, nullptr, FALSE);
}
void StopAll() {
    InterlockedIncrement(&g_connGen); InterlockedExchange(&g_running, 0);
    g_pingMs = -1; g_countryCode[0] = 0;
    SetWindowsProxy(false, g_cfg.localPort);
    if (g_listenSock != INVALID_SOCKET) { closesocket(g_listenSock); g_listenSock = INVALID_SOCKET; }
    if (g_serverThread) { WaitForSingleObject(g_serverThread, 2000); CloseHandle(g_serverThread); g_serverThread = nullptr; }
    if (g_tunProc || g_tunIfIndex) { StopTunEngine(); RestoreZapretIfNeeded(); g_zapretActive = IsZapretActive(); }
    UpdateTray();
}
void StartSelectedMode(HWND hwnd) {
    SaveConfig(); SetErrorMsg(nullptr);
    InterlockedIncrement(&g_connGen); InterlockedExchange(&g_upstreamProto, 0);
    g_pingMs = -1; g_countryCode[0] = 0;
    NetConfig cfg; GetNetConfig(&cfg);
    if (!cfg.ip[0] || cfg.socksPort <= 0) { SetErrorMsg(L"Ошибка · Проверьте IP и порт"); return; }

    if (g_mode == 0) {
        int pref = cfg.localPort > 0 ? cfg.localPort : 8888, bp = pref;
        g_listenSock = BindLocalProxyPort(pref, &bp);
        if (g_listenSock == INVALID_SOCKET) { SetErrorMsg(L"Ошибка · Не удалось открыть порт"); return; }
        if (bp != pref) {
            EnterCriticalSection(&g_cfgCs); g_cfg.localPort = bp; LeaveCriticalSection(&g_cfgCs);
            char b[16]; snprintf(b, sizeof(b), "%d", bp); if (hEditLPort) SetWindowTextA(hEditLPort, b); SaveConfig();
        }
        InterlockedExchange64(&g_bytesTotal, 0); InterlockedExchange(&g_activeConns, 0); InterlockedExchange(&g_running, 1);
        g_serverThread = CreateThread(nullptr, 0, ServerThread, nullptr, 0, nullptr);
        SetWindowsProxy(true, bp); UpdateTray(); LaunchProbeAsync(false);
        return;
    }

    wchar_t t1[MAX_PATH], t2[MAX_PATH];
    if (!FindTunBinaries(t1, t2)) {
        if (MessageBoxW(hwnd, L"Для режима TUN нужны tun2socks.exe и wintun.dll.\n\nСкачать с официальных источников с проверкой SHA-256?",
                        L"Драйвер TUN", MB_YESNO | MB_ICONQUESTION) == IDYES) StartDownloadTun(hwnd);
        return;
    }
    char sha[65] = {};
    if (!ComputeFileSha256Hex(t2, sha) || _stricmp(sha, WINTUN_DLL_SHA256) != 0) {
        int r = MessageBoxW(hwnd, L"Хеш SHA-256 файла wintun.dll отличается от официального Wintun 0.14.1.\n\nСкачать проверенную версию заново?\n• Да — перекачать\n• Нет — продолжить\n• Отмена — прервать",
                            L"Проверка Wintun", MB_YESNOCANCEL | MB_ICONWARNING);
        if (r == IDCANCEL) return;
        if (r == IDYES) { StartDownloadTun(hwnd); return; }
    }
    if (!IsElevated()) {
        if (MessageBoxW(hwnd, L"Для создания сетевого адаптера TUN требуются права администратора.\n\nПерезапустить программу с повышением прав?",
                        L"Права администратора", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
            ShellExecuteW(hwnd, L"runas", g_exePath, L"--autostart-tun", g_exeDir, SW_SHOWNORMAL);
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        return;
    }
    ClearSavedZapretState();
    if (IsZapretActive()) {
        int r = MessageBoxW(hwnd, L"Обнаружен запущенный обход DPI (Zapret / winws).\nВ режиме TUN он конфликтует с адаптером TunBridge и ломает загрузку сайтов.\n\nОстановить Запрет перед включением TUN?\n• Да — выключить Запрет и запустить TUN\n• Нет — запустить TUN без остановки",
                            L"Конфликт с Zapret", MB_YESNOCANCEL | MB_ICONWARNING);
        if (r == IDCANCEL) return;
        if (r == IDYES) { if (g_autoRestoreZapret) CaptureZapretStateBeforeStop(); StopZapret(); g_zapretActive = IsZapretActive(); }
    }
    if (InterlockedCompareExchange(&g_busy, 1, 0) == 0) {
        InterlockedExchange64(&g_bytesTotal, 0); RefreshControls();
        HANDLE ht = CreateThread(nullptr, 0, StartTunThread, nullptr, 0, nullptr);
        if (ht) CloseHandle(ht); else InterlockedExchange(&g_busy, 0);
    }
}
