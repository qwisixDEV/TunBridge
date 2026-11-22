#pragma once

// Иконка в трее рисуется кодом (QPainter/QPixmap), внешних PNG нет.

#include "tunbridge/core.hpp"

#include <QIcon>
#include <QObject>
#include <QString>

class QAction;
class QMenu;
class QSystemTrayIcon;

namespace tb {

QIcon make_app_icon(bool active);

class TrayIcon : public QObject {
    Q_OBJECT

public:
    explicit TrayIcon(QObject* parent = nullptr);
    ~TrayIcon() override;

    bool available() const;

signals:
    void showRequested();
    void toggleRequested();
    void exitRequested();

public slots:
    void setConnected(bool connected);
    void setMode(Mode mode);
    void setTelemetry(const QString& country, int pingMs);
    void setTooltip(const QString& text);

private:
    void refresh();

    QSystemTrayIcon* tray_{nullptr};
    QMenu* menu_{nullptr};
    QAction* toggleAction_{nullptr};
    bool connected_{false};
    Mode mode_{Mode::Proxy};
    QString country_;
    int pingMs_{-1};
    QString tooltipOverride_;
};

} // namespace tb
