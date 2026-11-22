#include "app_controller.hpp"

#include "main_window.hpp"
#include "tray_icon.hpp"

#include "tunbridge/download.hpp"
#include "tunbridge/health.hpp"
#include "tunbridge/scanner.hpp"
#include "tunbridge/traffic.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcessEnvironment>
#include <QStringList>
#include <QWidget>

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <thread>

namespace tb {
namespace {

bool file_is_executable(const QString& path)
{
    const QFileInfo info(path);
    return info.exists() && info.isExecutable();
}

QString lower_copy(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return QString::fromStdString(text);
}

bool contains_any(const QString& text, std::initializer_list<const char*> words)
{
    for (const char* word : words)
        if (text.contains(QLatin1String(word))) return true;
    return false;
}

QString health_hint(int err)
{
    switch (err) {
    case 1: return QStringLiteral("Нет связи");
    case 2: return QStringLiteral("Не прокси");
    case 3: return QStringLiteral("Неверный пароль");
    default: return QStringLiteral("Нет VPN-сети");
    }
}

QString net_error_text(const std::string& raw)
{
    const QString text = lower_copy(raw);
    if (contains_any(text, {"auth", "credential", "password"}))
        return QStringLiteral("Ошибка · Неверный логин/пароль");
    if (contains_any(text, {"unreach", "host", "connect"}))
        return QStringLiteral("Ошибка · Прокси недоступен");
    if (contains_any(text, {"proxy", "socks", "http"}))
        return QStringLiteral("Ошибка · Не SOCKS5/HTTP прокси");
    return QStringLiteral("Ошибка · Не удалось открыть порт");
}

QString helper_error_text(const std::string& raw)
{
    const QString text = lower_copy(raw);
    if (contains_any(text, {"auth", "credential", "password"}))
        return QStringLiteral("Ошибка · Неверный логин/пароль");
    if (contains_any(text, {"proxy", "upstream"}))
        return QStringLiteral("Ошибка · Прокси недоступен");
    if (contains_any(text, {"route", "dns"}))
        return QStringLiteral("Ошибка · Сбой маршрутов");
    if (contains_any(text, {"adapter", "interface", "tun create"}))
        return QStringLiteral("Ошибка · Адаптер TunBridge не создан");
    if (contains_any(text, {"tun2socks", "binary", "download", "sha256"}))
        return QStringLiteral("Ошибка · Сбой запуска tun2socks");
    return QStringLiteral("Ошибка · Сбой запуска TunBridge");
}

bool valid_endpoint(const NetConfig& cfg)
{
    return tb::is_safe_host(std::string(cfg.ip)) &&
           cfg.socksPort > 0 && cfg.socksPort <= 65535 &&
           cfg.localPort > 0 && cfg.localPort <= 65535;
}

} // namespace

std::string helper_binary_path()
{
    const QString overridePath =
        QProcessEnvironment::systemEnvironment().value(QStringLiteral("TB_HELPER_PATH"));
    if (!overridePath.isEmpty() && file_is_executable(overridePath))
        return overridePath.toStdString();

    QStringList candidates;
    candidates << (QCoreApplication::applicationDirPath() + QStringLiteral("/tunbridge-helper"));
    candidates << (QString::fromStdString(tb::data_home()) +
                   QStringLiteral("/tunbridge/bin/tunbridge-helper"));
    candidates << QStringLiteral("/usr/bin/tunbridge-helper");
    candidates << QStringLiteral("/usr/local/bin/tunbridge-helper");

    for (const QString& path : candidates)
        if (file_is_executable(path)) return path.toStdString();
    return candidates.first().toStdString();
}

AppController::AppController(const CliOptions& cli, const AppConfig& config,
                             MainWindow* window, TrayIcon* tray, QObject* parent)
    : QObject(parent),
      cli_(cli),
      config_(config),
      window_(window),
      tray_(tray),
      workerToken_(std::make_shared<std::atomic<bool>>(true)),
      scanCancel_(std::make_shared<std::atomic<bool>>(false)),
      testCancel_(std::make_shared<std::atomic<bool>>(false))
{
    wireUi();
    connect(&trafficTimer_, &QTimer::timeout, this, [this] { onTrafficTick(); });
}

AppController::~AppController()
{
    if (workerToken_) {
        workerToken_->store(false);
        workerToken_.reset(); // weak_ptr в фоновых потоках станет устаревшим
    }
    scanCancel_->store(true);
    testCancel_->store(true);
    stopAll();
}

void AppController::wireUi()
{
    connect(window_, &MainWindow::modeChanged,
            this, &AppController::onModeChanged);
    connect(window_, &MainWindow::connectRequested,
            this, &AppController::connectRequested);
    connect(window_, &MainWindow::scanRequested,
            this, &AppController::scanRequested);
    connect(window_, &MainWindow::testRequested,
            this, &AppController::testRequested);
    connect(window_, &MainWindow::settingsClosed,
            this, &AppController::onSettingsClosed);
    connect(window_, &MainWindow::minimizeToTrayChanged,
            this, &AppController::onMinimizeToTrayChanged);
    connect(window_, &MainWindow::autoStartChanged,
            this, &AppController::onAutoStartChanged);
    connect(window_, &MainWindow::autoRestoreZapretChanged,
            this, &AppController::onAutoRestoreZapretChanged);
    connect(window_, &MainWindow::downloadRequested,
            this, &AppController::startDownload);
    connect(window_, &MainWindow::stopZapretRequested,
            this, &AppController::stopZapret);
    connect(window_, &MainWindow::visibilityChanged,
            this, &AppController::onWindowVisibilityChanged);

    connect(tray_, &TrayIcon::showRequested, this, &AppController::activate);
    connect(tray_, &TrayIcon::toggleRequested, this, &AppController::toggleRequested);
    connect(tray_, &TrayIcon::exitRequested, this, [] { QCoreApplication::quit(); });
}

void AppController::initialize()
{
    mode_ = config_.mode;
    window_->setMode(mode_);
    window_->setToggles(config_.minimizeToTray, config_.autoStart,
                        config_.autoRestoreZapret);
    if (!tray_->available()) window_->setMinimizeToTray(false);
    window_->setConnected(false);
    window_->setStatus(QString(), false);
    refreshTunDriver();
    window_->setZapretActive(zapretDetected());
    refreshTelemetry();
    updateTray();
}

void AppController::activate()
{
    if (window_) window_->showAndRaise();
}

void AppController::readConfigFromWindow()
{
    tb::safe_copy(config_.net.ip, sizeof(config_.net.ip), window_->ip().toStdString().c_str());
    tb::safe_copy(config_.net.user, sizeof(config_.net.user), window_->user().toStdString().c_str());
    tb::safe_copy(config_.net.pass, sizeof(config_.net.pass), window_->password().toStdString().c_str());
    config_.net.socksPort = window_->socksPort();
    config_.net.localPort = window_->localPort();
}

void AppController::saveConfig()
{
    (void)tb::save_app_config(config_);
}

void AppController::onModeChanged(Mode mode)
{
    if (busy_ || running_) return;
    mode_ = mode;
    config_.mode = mode;
    saveConfig();
    refreshTelemetry();
    updateTray();
}

void AppController::onMinimizeToTrayChanged(bool enabled)
{
    config_.minimizeToTray = enabled;
    window_->setMinimizeToTray(enabled && tray_->available());
    saveConfig();
}

void AppController::onAutoStartChanged(bool enabled)
{
    CliOptions flags;
    flags.minimized = true; // автозапуск всегда в трей
    const std::string executable = QCoreApplication::applicationFilePath().toStdString();
    if (!tb::set_autostart(enabled, flags, executable)) {
        QMessageBox::warning(window_, QStringLiteral("Автозапуск"),
                             QStringLiteral("Не удалось изменить настройку автозапуска."));
        window_->setToggles(config_.minimizeToTray, config_.autoStart,
                            config_.autoRestoreZapret);
        return;
    }
    config_.autoStart = enabled;
    saveConfig();
}

void AppController::onAutoRestoreZapretChanged(bool enabled)
{
    config_.autoRestoreZapret = enabled;
    saveConfig();
}

void AppController::onSettingsClosed()
{
    readConfigFromWindow();
    saveConfig();
}

void AppController::onWindowVisibilityChanged(bool visible)
{
    if (!visible) {
        trafficTimer_.stop();
        return;
    }
    refreshTelemetry();
    updateTrafficTimer();
}

void AppController::setBusy(bool busy, const QString& text)
{
    busy_ = busy;
    window_->setBusy(busy, text);
}

void AppController::validateAndConnect()
{
    if (busy_ || running_) return;
    readConfigFromWindow();
    if (!valid_endpoint(config_.net)) {
        window_->setStatus(QStringLiteral("Ошибка · Проверьте IP и порт"), true);
        return;
    }
    saveConfig();
    ++connectGen_;
    setBusy(true, mode_ == Mode::Tun
                      ? QStringLiteral("Настройка адаптера TunBridge...")
                      : QStringLiteral("Подключение..."));
    if (mode_ == Mode::Tun)
        startTun();
    else
        startProxy();
}

void AppController::startProxy()
{
    engine_ = std::make_unique<NetEngine>(config_.net, &stats_);
    int boundPort = config_.net.localPort;
    std::string err;
    if (!engine_->start(&boundPort, &err)) {
        failConnect(net_error_text(err));
        return;
    }
    if (boundPort != config_.net.localPort) {
        config_.net.localPort = boundPort;
        window_->setLocalPort(boundPort);
        saveConfig();
    }

    stats_.rx.store(0);
    stats_.tx.store(0);
    stats_.connections.store(0);

    std::string proxyErr;
    if (!systemProxy_.enable(boundPort, &proxyErr)) {
        engine_->stop();
        engine_.reset();
        failConnect(QStringLiteral("Ошибка · Не удалось включить системный прокси"));
        return;
    }

    running_ = true;
    bytes_ = 0;
    lastTunTotal_ = 0;
    pingMs_ = -1;
    country_.clear();
    setBusy(false);
    window_->setConnected(true);
    refreshTelemetry();
    updateTray();
    updateTrafficTimer();

    // Одноразовая проверка при подключении, без периодических опросов.
    runHealthProbe(connectGen_, false);
}

void AppController::startTun()
{
    const QString tunBinary = QString::fromStdString(tb::tun2socks_path());
    const QFileInfo binaryInfo(tunBinary);
    if (!binaryInfo.exists() || !binaryInfo.isExecutable()) {
        setBusy(false);
        const auto answer = QMessageBox::question(
            window_, QStringLiteral("Драйвер TUN"),
            QStringLiteral("Для режима TUN нужен tun2socks.\n\nСкачать с официальных источников с проверкой SHA-256?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (answer == QMessageBox::Yes) startDownload();
        return;
    }

    bool stopZapret = false;
    if (zapretDetected()) {
        QMessageBox dialog(window_);
        dialog.setIcon(QMessageBox::Warning);
        dialog.setWindowTitle(QStringLiteral("Конфликт с Zapret"));
        dialog.setText(QStringLiteral(
            "Обнаружен запущенный обход DPI (Zapret / winws).\n"
            "В режиме TUN он конфликтует с адаптером TunBridge и ломает загрузку сайтов.\n\n"
            "Остановить Запрет перед включением TUN?\n"
            "• Да — выключить Запрет и запустить TUN\n"
            "• Нет — запустить TUN без остановки"));
        dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
        dialog.setDefaultButton(QMessageBox::Yes);
        const int answer = dialog.exec();
        if (answer == QMessageBox::Cancel) {
            setBusy(false);
            return;
        }
        stopZapret = (answer == QMessageBox::Yes);
    }

    HelperRequest request;
    request.action = HelperAction::StartTun;
    request.net = config_.net;
    request.proto = UpstreamProto::Socks5;
    request.dataDir = tb::data_home();
    request.runtimeDir = tb::runtime_dir();
    request.stopZapret = stopZapret;
    request.restoreZapret = stopZapret && config_.autoRestoreZapret;

    std::string err;
    const HelperReply reply = helper_.launch(request, helper_binary_path(), &err, 20000);
    if (!reply.ok) {
        helper_.disconnect();
        failConnect(helper_error_text(reply.message.empty() ? err : reply.message));
        return;
    }

    running_ = true;
    bytes_ = 0;
    lastTunTotal_ = tb::read_tun_traffic_bytes(QStringLiteral("tunbridge0").toStdString());
    pingMs_ = -1;
    country_.clear();
    setBusy(false);
    window_->setConnected(true);
    window_->setZapretActive(stopZapret ? false : zapretDetected());
    refreshTelemetry();
    updateTray();
    updateTrafficTimer();
    runHealthProbe(connectGen_, false);
}

void AppController::stopHelper(bool restoreZapret)
{
    if (!helper_.connected()) return;
    HelperRequest request;
    request.action = HelperAction::StopTun;
    request.runtimeDir = tb::runtime_dir();
    request.restoreZapret = restoreZapret;
    std::string err;
    // Даже если повторный запрос не пройдёт, закрытие канала вызовет
    // watchdog-откат настроек в хелпере.
    (void)helper_.launch(request, helper_binary_path(), &err, 5000);
    helper_.disconnect();
}

void AppController::failConnect(const QString& text)
{
    ++connectGen_;
    if (systemProxy_.active()) systemProxy_.disable();
    if (engine_) {
        engine_->stop();
        engine_.reset();
    }
    stopHelper(config_.autoRestoreZapret);
    trafficTimer_.stop();
    running_ = false;
    setBusy(false);
    window_->setConnected(false);
    window_->setStatus(text, true);
    refreshTelemetry();
    updateTray();
}

void AppController::disconnectRequested()
{
    if (!running_ || busy_) return;
    ++connectGen_;
    systemProxy_.disable();
    if (engine_) {
        engine_->stop();
        engine_.reset();
    }
    stopHelper(config_.autoRestoreZapret);

    running_ = false;
    bytes_ = 0;
    lastTunTotal_ = 0;
    pingMs_ = -1;
    country_.clear();
    trafficTimer_.stop();
    setBusy(false);
    window_->setConnected(false);
    window_->resetStatus();
    window_->setZapretActive(zapretDetected());
    refreshTelemetry();
    updateTray();
}

void AppController::toggleRequested()
{
    if (busy_) return;
    if (running_)
        disconnectRequested();
    else
        connectRequested();
}

void AppController::connectRequested()
{
    validateAndConnect();
}

void AppController::requestAutostartTun()
{
    activate();
    if (mode_ != Mode::Tun || config_.mode != Mode::Tun) {
        mode_ = Mode::Tun;
        config_.mode = Mode::Tun;
        window_->setMode(mode_);
        saveConfig();
        updateTray();
    }
    if (downloading_) {
        // --download-tun и --autostart-tun вместе: подключимся после загрузки.
        connectAfterDownload_ = true;
        return;
    }
    if (busy_ || running_) return;
    connectRequested();
}

void AppController::runHealthProbe(quint64 generation, bool fromButton)
{
    const NetConfig cfg = config_.net;
    // Слабый токен проверяется и в потоке, и в GUI-потоке: так callback
    // никогда не обратится к уже разрушенному контроллеру.
    std::weak_ptr<std::atomic<bool>> alive = workerToken_;
    QObject* selfObject = this;

    // Один поток на явное действие, никаких повторяющихся ping-таймеров.
    std::thread([alive, selfObject, cfg, generation, fromButton] {
        const HealthResult result = tb::probe_health(cfg, 5000);
        const auto token = alive.lock();
        if (!token || !token->load()) return;
        QCoreApplication* app = QCoreApplication::instance();
        if (!app) return;
        QMetaObject::invokeMethod(app, [alive, selfObject, result, generation, fromButton] {
            const auto guiToken = alive.lock();
            if (!guiToken || !guiToken->load()) return;
            QPointer<AppController> self(qobject_cast<AppController*>(selfObject));
            if (!self.isNull()) self->onHealthDone(generation, result, fromButton);
        }, Qt::QueuedConnection);
    }).detach();
}

void AppController::onHealthDone(quint64 generation, const HealthResult& result, bool fromButton)
{
    if (fromButton) {
        if (generation != testGen_) return;
        testing_ = false;
        window_->setTesting(false);
        const QString hint =
            result.err == 0
                ? (!result.country.empty()
                       ? QStringLiteral("ОК · %1 · %2 мс")
                             .arg(QString::fromStdString(result.country)).arg(result.pingMs)
                       : QStringLiteral("ОК · %1 мс").arg(result.pingMs))
                : health_hint(result.err);
        window_->setTestResult(result.err == 0, hint);
        return;
    }

    if (generation != connectGen_ || !running_) return;
    if (result.err == 0) {
        country_ = QString::fromStdString(result.country);
        pingMs_ = result.pingMs;
    } else {
        country_.clear();
        pingMs_ = -2; // "Нет выхода в сеть через прокси"
    }
    updateTray();
    refreshTelemetry();
}

void AppController::scanRequested()
{
    if (busy_ || scanning_ || running_) return;
    readConfigFromWindow();
    if (!valid_endpoint(config_.net)) {
        window_->setStatus(QStringLiteral("Ошибка · Проверьте IP и порт"), true);
        return;
    }
    saveConfig();

    ++scanGen_;
    const quint64 generation = scanGen_;
    scanning_ = true;
    window_->setScanning(true);
    scanCancel_ = std::make_shared<std::atomic<bool>>(false);

    const auto cancel = scanCancel_;
    const int port = config_.net.socksPort;
    std::weak_ptr<std::atomic<bool>> alive = workerToken_;
    QObject* selfObject = this;
    std::thread([alive, selfObject, cancel, port, generation] {
        const ScanResult result = tb::scan_lan(port, cancel.get(), 1200);
        const auto token = alive.lock();
        if (!token || !token->load()) return;
        QCoreApplication* app = QCoreApplication::instance();
        if (!app) return;
        QMetaObject::invokeMethod(app, [alive, selfObject, result, generation] {
            const auto guiToken = alive.lock();
            if (!guiToken || !guiToken->load()) return;
            QPointer<AppController> self(qobject_cast<AppController*>(selfObject));
            if (!self.isNull()) self->onScanDone(generation, result);
        }, Qt::QueuedConnection);
    }).detach();
}

void AppController::onScanDone(quint64 generation, const ScanResult& result)
{
    if (generation != scanGen_) return;
    scanning_ = false;
    window_->setScanning(false);
    window_->setScanResult(result.found, QString::fromStdString(result.ip));
    if (result.found) {
        tb::safe_copy(config_.net.ip, sizeof(config_.net.ip), result.ip.c_str());
        saveConfig();
    }
}

void AppController::testRequested()
{
    if (testing_ || busy_) return;
    readConfigFromWindow();
    if (!valid_endpoint(config_.net)) {
        window_->setStatus(QStringLiteral("Ошибка · Проверьте IP и порт"), true);
        return;
    }
    saveConfig();
    ++testGen_;
    testing_ = true;
    window_->setTesting(true);
    runHealthProbe(testGen_, true);
}

void AppController::startDownload()
{
    if (busy_) return;
    ++downloadGen_;
    const quint64 generation = downloadGen_;
    downloading_ = true;
    setBusy(true, QStringLiteral("Загрузка драйвера TUN..."));
    window_->resetStatus();

    std::weak_ptr<std::atomic<bool>> alive = workerToken_;
    QObject* selfObject = this;
    std::thread([alive, selfObject, generation] {
        std::string status;
        std::string error;
        const bool ok = tb::download_tun2socks(&status, &error);
        const auto token = alive.lock();
        if (!token || !token->load()) return;
        QCoreApplication* app = QCoreApplication::instance();
        if (!app) return;
        QMetaObject::invokeMethod(app, [alive, selfObject, generation, ok] {
            const auto guiToken = alive.lock();
            if (!guiToken || !guiToken->load()) return;
            QPointer<AppController> self(qobject_cast<AppController*>(selfObject));
            if (!self.isNull()) self->onDownloadDone(generation, ok);
        }, Qt::QueuedConnection);
    }).detach();
}

void AppController::onDownloadDone(quint64 generation, bool ok)
{
    if (generation != downloadGen_) return;
    downloading_ = false;
    setBusy(false);
    refreshTunDriver();
    window_->setStatus(ok ? QStringLiteral("Драйвер TUN установлен")
                          : QStringLiteral("Ошибка · Сбой загрузки / SHA-256"),
                       !ok);
    if (ok && connectAfterDownload_) {
        connectAfterDownload_ = false;
        connectRequested();
    }
}

void AppController::stopZapret()
{
    if (busy_) return;
    HelperClient client;
    HelperRequest request;
    request.action = HelperAction::StopZapret;
    request.runtimeDir = tb::runtime_dir();
    std::string err;
    const HelperReply reply = client.launch(request, helper_binary_path(), &err, 10000);
    client.disconnect();
    if (reply.ok) {
        window_->setZapretActive(false);
        window_->setStatus(QStringLiteral("Запрет остановлен"));
    } else {
        window_->setStatus(QStringLiteral("Ошибка · Не удалось остановить Zapret"), true);
    }
}

void AppController::updateTray()
{
    if (!tray_) return;
    tray_->setConnected(running_);
    tray_->setMode(mode_);
    tray_->setTelemetry(country_, pingMs_);
}

void AppController::refreshTelemetry()
{
    if (window_)
        window_->setTelemetry(country_, pingMs_, bytes_, running_, mode_);
}

void AppController::refreshTunDriver()
{
    if (!window_) return;
    const QFileInfo info(QString::fromStdString(tb::tun2socks_path()));
    window_->setTunDriverInstalled(info.exists() && info.isExecutable());
}

void AppController::updateTrafficTimer()
{
    const bool shouldRun = running_ && window_ && window_->isVisible() &&
                           !window_->isMinimized();
    if (shouldRun && !trafficTimer_.isActive())
        trafficTimer_.start(1000);
    else if (!shouldRun && trafficTimer_.isActive())
        trafficTimer_.stop();
}

void AppController::onTrafficTick()
{
    if (!running_) {
        trafficTimer_.stop();
        return;
    }
    if (mode_ == Mode::Tun) {
        const quint64 total = tb::read_tun_traffic_bytes("tunbridge0");
        if (lastTunTotal_ != 0 && total >= lastTunTotal_)
            bytes_ += total - lastTunTotal_;
        lastTunTotal_ = total;
    } else {
        bytes_ = static_cast<quint64>(stats_.rx.load()) +
                 static_cast<quint64>(stats_.tx.load());
    }
    refreshTelemetry();
}

bool AppController::zapretDetected() const
{
    const QDir proc(QStringLiteral("/proc"));
    const QStringList pids = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString& pid : pids) {
        bool numeric = false;
        pid.toInt(&numeric);
        if (!numeric) continue;
        QFile cmdline(QStringLiteral("/proc/%1/cmdline").arg(pid));
        if (!cmdline.open(QIODevice::ReadOnly)) continue;
        QByteArray data = cmdline.read(8192);
        data.replace('\0', ' ');
        if (data.contains("winws") || data.contains("zapret")) return true;
    }
    return false;
}

void AppController::stopAll()
{
    if (stopped_) return;
    stopped_ = true;
    ++connectGen_;
    trafficTimer_.stop();
    if (systemProxy_.active()) systemProxy_.disable();
    if (engine_) {
        engine_->stop();
        engine_.reset();
    }
    stopHelper(config_.autoRestoreZapret);
    running_ = false;
}

} // namespace tb
