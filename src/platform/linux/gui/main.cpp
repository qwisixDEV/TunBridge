// TunBridge Linux GUI: unprivileged Qt6 Widgets front-end.
// Привилегированные операции выполняет отдельный helper через pkexec.

#include "app_controller.hpp"
#include "main_window.hpp"
#include "single_instance.hpp"
#include "tray_icon.hpp"

#include "tunbridge/core.hpp"
#include "tunbridge/helper_protocol.hpp"
#include "tunbridge/xdg.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QMessageBox>
#include <QMetaObject>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
    QApplication::setAttribute(Qt::AA_DontCreateNativeWidgetSiblings, true);
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("TunBridge"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("tunbridge.local"));
    QCoreApplication::setApplicationName(QStringLiteral("TunBridge"));
    QApplication::setApplicationDisplayName(QStringLiteral("TunBridge"));

    const tb::CliOptions cli = tb::parse_cli(argc, argv);

#ifndef _WIN32
    if (::geteuid() == 0) {
        QMessageBox::critical(nullptr, QStringLiteral("Ошибка"),
                              QStringLiteral("TunBridge не должен запускаться с правами root.\n"
                                             "Привилегированные операции выполняет helper через pkexec."));
        return 1;
    }
#endif

    // Быстрый путь из меню "Остановить Zapret": только helper, без GUI.
    if (cli.stopZapret) {
        tb::HelperClient client;
        tb::HelperRequest request;
        request.action = tb::HelperAction::StopZapret;
        request.runtimeDir = tb::runtime_dir();
        std::string err;
        const tb::HelperReply reply =
            client.launch(request, tb::helper_binary_path(), &err, 10000);
        client.disconnect();
        if (!reply.ok) std::fprintf(stderr, "Ошибка остановки Zapret: %s\n", err.c_str());
        return reply.ok ? 0 : 1;
    }

    tb::SingleInstance instance;
    const tb::SingleInstanceResult instanceResult = instance.acquire();
    if (instanceResult == tb::SingleInstanceResult::AlreadyRunning) {
        // Команды от второго процесса исполняет уже работающий GUI.
        if (cli.downloadTun)
            (void)tb::send_command(tb::InstanceCommand::DownloadTun);
        if (cli.autostartTun)
            (void)tb::send_command(tb::InstanceCommand::AutostartTun);
        if (!cli.downloadTun && !cli.autostartTun)
            (void)tb::send_activate();
        return 0;
    }

    tb::AppConfig config;
    (void)tb::load_app_config(config);
    if (cli.autostartTun) config.mode = tb::Mode::Tun;

    tb::MainWindow window;
    tb::TrayIcon tray;
    tb::AppController controller(cli, config, &window, &tray);

    QObject::connect(&instance, &tb::SingleInstance::activateRequested,
                     &controller, [&controller] { controller.activate(); });
    QObject::connect(&instance, &tb::SingleInstance::autostartTunRequested,
                     &controller, [&controller] { controller.requestAutostartTun(); });
    QObject::connect(&instance, &tb::SingleInstance::downloadTunRequested,
                     &controller, [&controller] { controller.startDownload(); });
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &controller,
                     [&controller] { controller.stopAll(); });

    controller.initialize();
    if (!cli.minimized || !tray.available()) window.show();

    // Специальные флаги должны сработать уже после старта event loop.
    if (cli.autostartTun || cli.downloadTun) {
        QMetaObject::invokeMethod(&controller, [&controller, cli] {
            if (cli.downloadTun) controller.startDownload();
            if (cli.autostartTun) controller.requestAutostartTun();
        }, Qt::QueuedConnection);
    }

    return app.exec();
}
