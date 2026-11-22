#include "tray_icon.hpp"

#include <QAction>
#include <QColor>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPen>
#include <QPointF>
#include <QRectF>
#include <QSystemTrayIcon>

#include <initializer_list>

namespace tb {

QIcon make_app_icon(bool active)
{
    QIcon icon;
    for (int size : {16, 22, 24, 32, 48, 64}) {
        QPixmap pix(size, size);
        pix.fill(Qt::transparent);
        QPainter p(&pix);
        p.setRenderHint(QPainter::Antialiasing, true);

        const qreal s = static_cast<qreal>(size) / 32.0;
        const qreal pad = size <= 16 ? 0.5 : 1.5 * s;
        const qreal radius = size <= 16 ? 3.5 : 7.0 * s;

        p.setBrush(QColor(QStringLiteral("#222222")));
        p.setPen(QPen(active ? QColor(QStringLiteral("#3a4c44"))
                             : QColor(QStringLiteral("#3e3e3e")),
                      size <= 16 ? 1.0 : 1.0 * s));
        p.drawRoundedRect(QRectF(pad, pad, size - 2 * pad, size - 2 * pad),
                          radius, radius);

        // Арка (как в оригинальной WIN32-иконке).
        const qreal left = 9.5 * s;
        const qreal right = 22.5 * s;
        const qreal top = 9.0 * s;
        const qreal middle = 15.5 * s;
        const qreal bottom = 22.0 * s;
        QPainterPath arch;
        arch.moveTo(left, bottom);
        arch.lineTo(left, middle);
        arch.arcTo(QRectF(left, top, right - left, (middle - top) * 2), 180, 180);
        arch.lineTo(right, bottom);
        QPen archPen(active ? QColor(QStringLiteral("#f0f4f2"))
                            : QColor(QStringLiteral("#919191")),
                     size <= 16 ? 1.8 : 2.8 * s);
        archPen.setCapStyle(Qt::RoundCap);
        archPen.setJoinStyle(Qt::RoundJoin);
        p.setPen(archPen);
        p.setBrush(Qt::NoBrush);
        p.drawPath(arch);

        // Зелёная (или серая) точка.
        const qreal dot = size <= 16 ? 4.2 : 6.4 * s;
        p.setPen(Qt::NoPen);
        p.setBrush(active ? QColor(QStringLiteral("#10b981"))
                          : QColor(QStringLiteral("#6c6c6c")));
        p.drawEllipse(QPointF(16.0 * s, 18.0 * s), dot / 2, dot / 2);

        icon.addPixmap(pix);
    }
    return icon;
}

TrayIcon::TrayIcon(QObject* parent)
    : QObject(parent)
{
    tray_ = new QSystemTrayIcon(make_app_icon(false), this);
    tray_->setToolTip(QStringLiteral("TunBridge — Отключено"));

    menu_ = new QMenu();
    QAction* open = menu_->addAction(QStringLiteral("Открыть"));
    toggleAction_ = menu_->addAction(QStringLiteral("Подключить"));
    menu_->addSeparator();
    QAction* quit = menu_->addAction(QStringLiteral("Выход"));
    tray_->setContextMenu(menu_);

    connect(open, &QAction::triggered, this, [this] { emit showRequested(); });
    connect(toggleAction_, &QAction::triggered, this, [this] { emit toggleRequested(); });
    connect(quit, &QAction::triggered, this, [this] { emit exitRequested(); });
    connect(tray_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::DoubleClick ||
                    reason == QSystemTrayIcon::Trigger)
                    emit showRequested();
            });

    if (QSystemTrayIcon::isSystemTrayAvailable()) tray_->show();
}

TrayIcon::~TrayIcon()
{
    if (tray_) {
        tray_->hide();
        tray_->setContextMenu(nullptr);
    }
    delete menu_;
    menu_ = nullptr;
}

bool TrayIcon::available() const
{
    return QSystemTrayIcon::isSystemTrayAvailable();
}

void TrayIcon::setConnected(bool connected)
{
    connected_ = connected;
    refresh();
}

void TrayIcon::setMode(Mode mode)
{
    mode_ = mode;
    refresh();
}

void TrayIcon::setTelemetry(const QString& country, int pingMs)
{
    country_ = country;
    pingMs_ = pingMs;
    refresh();
}

void TrayIcon::setTooltip(const QString& text)
{
    tooltipOverride_ = text;
    refresh();
}

void TrayIcon::refresh()
{
    tray_->setIcon(make_app_icon(connected_));
    toggleAction_->setText(connected_ ? QStringLiteral("Отключить")
                                      : QStringLiteral("Подключить"));

    if (!tooltipOverride_.isEmpty()) {
        tray_->setToolTip(tooltipOverride_);
    } else if (connected_ && !country_.isEmpty() && pingMs_ >= 0) {
        tray_->setToolTip(QStringLiteral("TunBridge · %1 · %2 мс")
                              .arg(country_).arg(pingMs_));
    } else {
        const QString suffix =
            connected_ ? (mode_ == Mode::Tun ? QStringLiteral("Подключено (TUN)")
                                             : QStringLiteral("Подключено (Прокси)"))
                       : QStringLiteral("Отключено");
        tray_->setToolTip(QStringLiteral("TunBridge — %1").arg(suffix));
    }
}

} // namespace tb
