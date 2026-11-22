#pragma once

// Оркестратор GUI: режимы, хелпер, системный прокси, фоновые задачи и трафик.

#include "tunbridge/core.hpp"
#include "tunbridge/health.hpp"
#include "tunbridge/helper_protocol.hpp"
#include "tunbridge/net_engine.hpp"
#include "tunbridge/scanner.hpp"
#include "tunbridge/system_proxy.hpp"
#include "tunbridge/xdg.hpp"

#include <QObject>
#include <QString>
#include <QTimer>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace tb {

class MainWindow;
class TrayIcon;

// Абсолютный путь к привилегированному helper'у (переменная TB_HELPER_PATH,
// каталог приложения, XDG data, /usr/bin, /usr/local/bin).
std::string helper_binary_path();

class AppController : public QObject {
    Q_OBJECT

public:
    AppController(const CliOptions& cli, const AppConfig& config,
                  MainWindow* window, TrayIcon* tray, QObject* parent = nullptr);
    ~AppController() override;

    void initialize();
    void activate();
    void stopAll();

public slots:
    // Действия пользователя.
    void connectRequested();
    void disconnectRequested();
    void toggleRequested();
    void scanRequested();
    void testRequested();
    void startDownload();
    void stopZapret();
    void onModeChanged(Mode mode);
    void onMinimizeToTrayChanged(bool enabled);
    void onAutoStartChanged(bool enabled);
    void onAutoRestoreZapretChanged(bool enabled);
    void onSettingsClosed();
    void onWindowVisibilityChanged(bool visible);
    void requestAutostartTun();

private:
    void wireUi();
    void readConfigFromWindow();
    void saveConfig();
    void validateAndConnect();
    void startProxy();
    void startTun();
    void failConnect(const QString& text);
    void stopHelper(bool restoreZapret);
    void setBusy(bool busy, const QString& text = QString());
    void runHealthProbe(quint64 generation, bool fromButton);
    void onHealthDone(quint64 generation, const HealthResult& result, bool fromButton);
    void onScanDone(quint64 generation, const ScanResult& result);
    void onDownloadDone(quint64 generation, bool ok);
    void updateTray();
    void refreshTelemetry();
    void refreshTunDriver();
    void updateTrafficTimer();
    void onTrafficTick();
    bool zapretDetected() const;

    CliOptions cli_;
    AppConfig config_;
    MainWindow* window_{nullptr};
    TrayIcon* tray_{nullptr};

    NetStats stats_;
    std::unique_ptr<NetEngine> engine_;
    SystemProxy systemProxy_;
    HelperClient helper_;
    QTimer trafficTimer_;

    // Отмена фоновых задач и защита от callback'ов после разрушения.
    std::shared_ptr<std::atomic<bool>> workerToken_;
    std::shared_ptr<std::atomic<bool>> scanCancel_;
    std::shared_ptr<std::atomic<bool>> testCancel_;

    quint64 connectGen_{0};
    quint64 scanGen_{0};
    quint64 testGen_{0};
    quint64 downloadGen_{0};

    bool running_{false};
    bool busy_{false};
    bool stopped_{false};
    bool scanning_{false};
    bool testing_{false};
    bool downloading_{false};
    bool connectAfterDownload_{false};
    Mode mode_{Mode::Proxy};
    int pingMs_{-1};
    QString country_;
    quint64 bytes_{0};
    quint64 lastTunTotal_{0};
};

} // namespace tb
