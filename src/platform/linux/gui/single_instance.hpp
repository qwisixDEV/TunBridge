#pragma once

// Один экземпляр GUI на пользователя: AF_UNIX сокет в $XDG_RUNTIME_DIR.

#include <QObject>
#include <QString>

#include <memory>

class QLocalServer;

namespace tb {

enum class SingleInstanceResult { Primary, AlreadyRunning, Failed };
enum class InstanceCommand { Activate, AutostartTun, DownloadTun };

class SingleInstance : public QObject {
    Q_OBJECT

public:
    explicit SingleInstance(QObject* parent = nullptr);
    ~SingleInstance() override;

    static QString socketPath();

    // Возвращает AlreadyRunning, если живой процесс уже слушает сокет.
    // "Осиротевший" файл сокета удаляется автоматически.
    SingleInstanceResult acquire();
    bool isPrimary() const;

signals:
    void activateRequested();
    void autostartTunRequested();
    void downloadTunRequested();

private:
    void onNewConnection();

    std::unique_ptr<QLocalServer> server_;
};

// Команды уже запущенному экземпляру (best effort).
bool send_command(InstanceCommand command);
bool send_activate();

} // namespace tb
