#include "single_instance.hpp"

#include "tunbridge/xdg.hpp"

#include <QByteArray>
#include <QDir>
#include <QIODevice>
#include <QLocalServer>
#include <QLocalSocket>

#include <memory>

namespace tb {
namespace {

bool peer_alive(const QString& path)
{
    QLocalSocket socket;
    socket.connectToServer(path, QIODevice::WriteOnly);
    return socket.waitForConnected(250);
}

QByteArray command_name(InstanceCommand command)
{
    switch (command) {
    case InstanceCommand::AutostartTun: return QByteArray("autostart-tun");
    case InstanceCommand::DownloadTun:  return QByteArray("download-tun");
    case InstanceCommand::Activate:     break;
    }
    return QByteArray("activate");
}

} // namespace

SingleInstance::SingleInstance(QObject* parent)
    : QObject(parent)
{
}

SingleInstance::~SingleInstance() = default;

QString SingleInstance::socketPath()
{
    QString dir = QString::fromStdString(tb::runtime_dir());
    if (dir.isEmpty()) dir = QDir::tempPath();
    QDir().mkpath(dir);
    return dir + QStringLiteral("/tunbridge.sock");
}

SingleInstanceResult SingleInstance::acquire()
{
    const QString path = socketPath();

    const auto try_listen = [this, &path] {
        server_ = std::make_unique<QLocalServer>(this);
        server_->setSocketOptions(QLocalServer::UserAccessOption);
        return server_->listen(path);
    };
    const auto wire_server = [this] {
        connect(server_.get(), &QLocalServer::newConnection,
                this, &SingleInstance::onNewConnection);
    };

    // Сначала пробуем слушать: так мы никогда не удалим сокет живого процесса.
    if (try_listen()) {
        wire_server();
        return SingleInstanceResult::Primary;
    }
    if (peer_alive(path)) {
        server_.reset();
        return SingleInstanceResult::AlreadyRunning;
    }

    // Осиротевший файл сокета — безопасная гонка только после проверки peer.
    server_.reset();
    QLocalServer::removeServer(path);
    if (try_listen()) {
        wire_server();
        return SingleInstanceResult::Primary;
    }

    const bool busy = peer_alive(path);
    server_.reset();
    return busy ? SingleInstanceResult::AlreadyRunning
                : SingleInstanceResult::Failed;
}

bool SingleInstance::isPrimary() const
{
    return server_ && server_->isListening();
}

void SingleInstance::onNewConnection()
{
    if (!server_) return;
    while (server_->hasPendingConnections()) {
        QLocalSocket* socket = server_->nextPendingConnection();
        if (!socket) break;

        auto buffer = std::make_shared<QByteArray>();
        connect(socket, &QLocalSocket::readyRead, this,
                [this, socket, buffer] {
                    buffer->append(socket->readAll());
                    int pos = 0;
                    while ((pos = buffer->indexOf('\n')) >= 0) {
                        const QByteArray line = buffer->left(pos).trimmed();
                        buffer->remove(0, pos + 1);
                        if (line == "activate") emit activateRequested();
                        else if (line == "autostart-tun") emit autostartTunRequested();
                        else if (line == "download-tun") emit downloadTunRequested();
                    }
                    socket->disconnectFromServer();
                });
        connect(socket, &QLocalSocket::disconnected,
                socket, &QObject::deleteLater);
    }
}

bool send_command(InstanceCommand command)
{
    QLocalSocket socket;
    socket.connectToServer(SingleInstance::socketPath(), QIODevice::WriteOnly);
    if (!socket.waitForConnected(300)) return false;
    const QByteArray payload = command_name(command) + "\n";
    socket.write(payload);
    socket.flush();
    return socket.waitForBytesWritten(300);
}

bool send_activate()
{
    return send_command(InstanceCommand::Activate);
}

} // namespace tb
