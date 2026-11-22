#include "main_window.hpp"
#include "tray_icon.hpp" // make_app_icon()

#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QHideEvent>
#include <QIcon>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPixmap>
#include <QPen>
#include <QPointF>
#include <QPushButton>
#include <QRectF>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QStyle>
#include <QtMath>

namespace tb {
namespace {

enum class UiIcon {
    Tray, Settings, Back, Scan, Busy, Check, Cross,
    Eye, EyeOff, Download, Stop
};

QIcon button_icon(UiIcon kind, const QColor& color)
{
    QPixmap pix(24, 24);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    p.setRenderHint(QPainter::Antialiasing, true);
    QPen pen(color, 1.8);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    switch (kind) {
    case UiIcon::Tray:
        p.drawRoundedRect(QRectF(3, 4, 18, 13), 2, 2);
        p.drawLine(QPointF(12, 7), QPointF(12, 13));
        p.drawLine(QPointF(9, 10), QPointF(12, 13));
        p.drawLine(QPointF(15, 10), QPointF(12, 13));
        break;
    case UiIcon::Settings:
        p.drawEllipse(QRectF(9, 9, 6, 6));
        for (int i = 0; i < 8; ++i) {
            const double a = i * 3.14159265358979323846 / 4.0;
            const double c = 12.0 + 5.2 * qCos(a);
            const double s = 12.0 + 5.2 * qSin(a);
            p.drawLine(QPointF(12 + 3.6 * qCos(a), 12 + 3.6 * qSin(a)),
                       QPointF(c, s));
        }
        break;
    case UiIcon::Back:
        p.drawLine(QPointF(6, 12), QPointF(19, 12));
        p.drawLine(QPointF(11, 7), QPointF(6, 12));
        p.drawLine(QPointF(6, 12), QPointF(11, 17));
        break;
    case UiIcon::Scan:
        p.drawEllipse(QRectF(4, 4, 11, 11));
        p.drawLine(QPointF(12.5, 12.5), QPointF(19, 19));
        break;
    case UiIcon::Busy:
        p.drawArc(QRectF(4, 4, 16, 16), 0, 285 * 16);
        break;
    case UiIcon::Check:
        p.drawLine(QPointF(4, 12), QPointF(10, 18));
        p.drawLine(QPointF(10, 18), QPointF(20, 6));
        break;
    case UiIcon::Cross:
        p.drawLine(QPointF(6, 6), QPointF(18, 18));
        p.drawLine(QPointF(18, 6), QPointF(6, 18));
        break;
    case UiIcon::Eye:
        p.drawEllipse(QRectF(2, 7, 20, 10));
        p.drawEllipse(QRectF(9, 9, 6, 6));
        break;
    case UiIcon::EyeOff:
        p.drawEllipse(QRectF(2, 7, 20, 10));
        p.drawEllipse(QRectF(9, 9, 6, 6));
        p.drawLine(QPointF(3, 21), QPointF(21, 3));
        break;
    case UiIcon::Download:
        p.drawLine(QPointF(12, 3), QPointF(12, 15));
        p.drawLine(QPointF(7, 10), QPointF(12, 15));
        p.drawLine(QPointF(12, 15), QPointF(17, 10));
        p.drawLine(QPointF(4, 20), QPointF(20, 20));
        break;
    case UiIcon::Stop:
        p.setBrush(color);
        p.drawRoundedRect(QRectF(6, 6, 12, 12), 2, 2);
        break;
    }
    return QIcon(pix);
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QWidget(parent)
{
    setWindowTitle(QStringLiteral("TunBridge"));
    setWindowIcon(make_app_icon(true));
    setFixedSize(360, 400);
    buildUi();
    applyStyle();
    showMain();
}

MainWindow::~MainWindow() = default;

QString MainWindow::ip() const { return ipEdit_->text().trimmed(); }
int MainWindow::socksPort() const { return socksPortEdit_->text().trimmed().toInt(); }
int MainWindow::localPort() const { return localPortEdit_->text().trimmed().toInt(); }
QString MainWindow::user() const { return userEdit_->text(); }
QString MainWindow::password() const { return passEdit_->text(); }

void MainWindow::buildUi()
{
    const QColor muted(QStringLiteral("#9a9a9a"));
    const QColor iconIdle(QStringLiteral("#d6d6d6"));
    const QColor danger(QStringLiteral("#d94848"));

    root_ = new QWidget(this);
    root_->setObjectName(QStringLiteral("root"));
    root_->setGeometry(0, 0, 360, 468);

    mainControls_ = new QWidget(root_);
    mainControls_->setObjectName(QStringLiteral("page"));
    mainControls_->setGeometry(0, 0, 360, 400);
    settingsControls_ = new QWidget(root_);
    settingsControls_->setObjectName(QStringLiteral("page"));
    settingsControls_->setGeometry(0, 0, 360, 468);

    auto makeLabel = [](QWidget* parent, const QString& name, const QString& text,
                        int x, int y, int w, int h) {
        QLabel* label = new QLabel(parent);
        label->setObjectName(name);
        label->setText(text);
        label->setGeometry(x, y, w, h);
        return label;
    };
    auto makeButton = [](QWidget* parent, const QString& name, const QString& text,
                         int x, int y, int w, int h) {
        QPushButton* button = new QPushButton(parent);
        button->setObjectName(name);
        button->setText(text);
        button->setGeometry(x, y, w, h);
        button->setCursor(Qt::PointingHandCursor);
        return button;
    };
    auto makeEdit = [](QWidget* parent, const QString& name, int x, int y, int w, int h) {
        QLineEdit* edit = new QLineEdit(parent);
        edit->setObjectName(name);
        edit->setGeometry(x, y, w, h);
        return edit;
    };

    // --- Главный экран ----------------------------------------------------
    titleLabel_ = makeLabel(mainControls_, QStringLiteral("title"),
                            QStringLiteral("TunBridge"), 24, 16, 224, 32);
    trayButton_ = makeButton(mainControls_, QStringLiteral("iconButton"), QString(), 264, 16, 32, 32);
    trayButton_->setIcon(button_icon(UiIcon::Tray, muted));
    trayButton_->setIconSize(QSize(20, 20));
    trayButton_->setToolTip(QStringLiteral("Свернуть в трей"));
    settingsButton_ = makeButton(mainControls_, QStringLiteral("iconButton"), QString(), 304, 16, 32, 32);
    settingsButton_->setIcon(button_icon(UiIcon::Settings, muted));
    settingsButton_->setIconSize(QSize(20, 20));
    settingsButton_->setToolTip(QStringLiteral("Настройки"));
    divider_ = makeLabel(mainControls_, QStringLiteral("divider"), QString(), 24, 56, 312, 1);

    makeLabel(mainControls_, QStringLiteral("segmented"), QString(), 24, 72, 312, 40);
    modeProxyButton_ = makeButton(mainControls_, QStringLiteral("modeButton"),
                                  QStringLiteral("Системный прокси"), 28, 76, 150, 32);
    modeTunButton_ = makeButton(mainControls_, QStringLiteral("modeButton"),
                                QStringLiteral("Весь трафик (TUN)"), 182, 76, 150, 32);
    modeProxyButton_->setCheckable(true);
    modeTunButton_->setCheckable(true);
    modeProxyButton_->setAutoExclusive(true);
    modeTunButton_->setAutoExclusive(true);

    ipCaption_ = makeLabel(mainControls_, QStringLiteral("muted"),
                           QStringLiteral("IP телефона / прокси"), 24, 136, 132, 16);
    ipHint_ = makeLabel(mainControls_, QStringLiteral("hint"), QString(), 156, 136, 180, 16);
    ipHint_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    ipHint_->setProperty("state", QStringLiteral("idle"));

    ipEdit_ = makeEdit(mainControls_, QStringLiteral("input"), 24, 160, 232, 32);
    ipEdit_->setMaxLength(127);
    ipEdit_->setPlaceholderText(QString());
    scanButton_ = makeButton(mainControls_, QStringLiteral("iconButton"), QString(), 264, 160, 32, 32);
    scanButton_->setIcon(button_icon(UiIcon::Scan, muted));
    scanButton_->setIconSize(QSize(20, 20));
    scanButton_->setToolTip(QStringLiteral("Найти прокси в сети"));
    testButton_ = makeButton(mainControls_, QStringLiteral("iconButton"), QString(), 304, 160, 32, 32);
    testButton_->setIcon(button_icon(UiIcon::Check, muted));
    testButton_->setIconSize(QSize(20, 20));
    testButton_->setToolTip(QStringLiteral("Проверить связь, пинг и страну"));

    statusPanel_ = makeLabel(mainControls_, QStringLiteral("statusPanel"), QString(), 24, 224, 312, 136);
    statusDot_ = makeLabel(mainControls_, QStringLiteral("statusDot"), QString(), 40, 310, 8, 8);
    statusDot_->setProperty("state", QStringLiteral("idle"));
    statusText_ = makeLabel(mainControls_, QStringLiteral("statusText"), QString(), 56, 304, 272, 24);
    statusText_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    statusText_->setProperty("state", QStringLiteral("idle"));

    toggleButton_ = makeButton(mainControls_, QStringLiteral("toggleButton"),
                               QStringLiteral("Подключить"), 80, 252, 200, 40);
    toggleButton_->setProperty("connected", false);

    // --- Экран настроек ---------------------------------------------------
    makeLabel(settingsControls_, QStringLiteral("title"),
              QStringLiteral("Настройки"), 64, 16, 240, 32);
    backButton_ = makeButton(settingsControls_, QStringLiteral("iconButton"), QString(), 24, 16, 32, 32);
    backButton_->setIcon(button_icon(UiIcon::Back, iconIdle));
    backButton_->setIconSize(QSize(20, 20));
    backButton_->setToolTip(QStringLiteral("Назад"));
    divider2_ = makeLabel(settingsControls_, QStringLiteral("divider"), QString(), 24, 56, 312, 1);

    socksCaption_ = makeLabel(settingsControls_, QStringLiteral("muted"),
                              QStringLiteral("Порт прокси"), 24, 68, 152, 16);
    localCaption_ = makeLabel(settingsControls_, QStringLiteral("muted"),
                              QStringLiteral("Локальный порт"), 184, 68, 152, 16);
    socksPortEdit_ = makeEdit(settingsControls_, QStringLiteral("input"), 24, 88, 152, 30);
    localPortEdit_ = makeEdit(settingsControls_, QStringLiteral("input"), 184, 88, 152, 30);
    socksPortEdit_->setValidator(new QIntValidator(1, 65535, socksPortEdit_));
    localPortEdit_->setValidator(new QIntValidator(1, 65535, localPortEdit_));
    socksPortEdit_->setMaxLength(5);
    localPortEdit_->setMaxLength(5);

    userCaption_ = makeLabel(settingsControls_, QStringLiteral("muted"),
                             QStringLiteral("Логин (если нужен)"), 24, 130, 312, 16);
    userEdit_ = makeEdit(settingsControls_, QStringLiteral("input"), 24, 150, 312, 30);
    userEdit_->setMaxLength(255);
    passCaption_ = makeLabel(settingsControls_, QStringLiteral("muted"),
                             QStringLiteral("Пароль (если нужен)"), 24, 192, 312, 16);
    passEdit_ = makeEdit(settingsControls_, QStringLiteral("input"), 24, 212, 312, 30);
    passEdit_->setMaxLength(255);
    passEdit_->setEchoMode(QLineEdit::Password);
    passEdit_->setTextMargins(0, 0, 34, 0);
    showPassButton_ = makeButton(settingsControls_, QStringLiteral("iconButton"), QString(), 306, 214, 26, 26);
    showPassButton_->setIcon(button_icon(UiIcon::Eye, muted));
    showPassButton_->setIconSize(QSize(16, 16));
    showPassButton_->setToolTip(QStringLiteral("Показать / скрыть пароль"));
    makeLabel(settingsControls_, QStringLiteral("divider"), QString(), 24, 258, 312, 1);

    minimizeCheck_ = new QCheckBox(QStringLiteral("Сворачивать в трей"), settingsControls_);
    minimizeCheck_->setObjectName(QStringLiteral("switchCheck"));
    minimizeCheck_->setGeometry(24, 272, 312, 32);
    minimizeCheck_->setCursor(Qt::PointingHandCursor);
    minimizeCheck_->setToolTip(QStringLiteral("Сворачивать в трей при минимизации"));
    autoStartCheck_ = new QCheckBox(QStringLiteral("Автозапуск в трей"), settingsControls_);
    autoStartCheck_->setObjectName(QStringLiteral("switchCheck"));
    autoStartCheck_->setGeometry(24, 308, 312, 32);
    autoStartCheck_->setCursor(Qt::PointingHandCursor);
    autoStartCheck_->setToolTip(QStringLiteral("Запускать при входе в систему в трей"));
    autoZapretCheck_ = new QCheckBox(QStringLiteral("Автовозврат Zapret"), settingsControls_);
    autoZapretCheck_->setObjectName(QStringLiteral("switchCheck"));
    autoZapretCheck_->setGeometry(24, 344, 312, 32);
    autoZapretCheck_->setCursor(Qt::PointingHandCursor);
    autoZapretCheck_->setToolTip(QStringLiteral("Возвращать Zapret после выключения TUN"));

    driverCaption_ = makeLabel(settingsControls_, QStringLiteral("rowText"),
                               QStringLiteral("Драйвер TUN"), 24, 384, 160, 32);
    driverValue_ = makeLabel(settingsControls_, QStringLiteral("rowValue"),
                             QStringLiteral("Не найден"), 188, 384, 108, 32);
    driverValue_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    driverValue_->setProperty("state", QStringLiteral("error"));
    zapretCaption_ = makeLabel(settingsControls_, QStringLiteral("rowText"),
                               QStringLiteral("Обход DPI (Zapret)"), 24, 422, 160, 32);
    zapretValue_ = makeLabel(settingsControls_, QStringLiteral("rowValue"),
                             QStringLiteral("Остановлен"), 188, 422, 108, 32);
    zapretValue_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    zapretValue_->setProperty("state", QStringLiteral("idle"));

    downloadButton_ = makeButton(settingsControls_, QStringLiteral("iconButton"), QString(), 304, 384, 32, 32);
    downloadButton_->setIcon(button_icon(UiIcon::Download, muted));
    downloadButton_->setIconSize(QSize(20, 20));
    downloadButton_->setToolTip(QStringLiteral("Скачать / проверить драйвер TUN (SHA-256)"));
    stopZapretButton_ = makeButton(settingsControls_, QStringLiteral("iconButtonDanger"), QString(), 304, 422, 32, 32);
    stopZapretButton_->setIcon(button_icon(UiIcon::Stop, danger));
    stopZapretButton_->setIconSize(QSize(18, 18));
    stopZapretButton_->setToolTip(QStringLiteral("Остановить Zapret / WinDivert"));
    stopZapretButton_->setProperty("active", false);

    // --- Сигналы элементов ------------------------------------------------
    connect(modeProxyButton_, &QPushButton::clicked, this, [this] {
        setMode(Mode::Proxy);
        emit modeChanged(Mode::Proxy);
    });
    connect(modeTunButton_, &QPushButton::clicked, this, [this] {
        setMode(Mode::Tun);
        emit modeChanged(Mode::Tun);
    });
    connect(toggleButton_, &QPushButton::clicked, this, [this] { emit connectRequested(); });
    connect(scanButton_, &QPushButton::clicked, this, [this] { emit scanRequested(); });
    connect(testButton_, &QPushButton::clicked, this, [this] { emit testRequested(); });
    connect(settingsButton_, &QPushButton::clicked, this, [this] { showSettings(); });
    connect(backButton_, &QPushButton::clicked, this, [this] {
        showMain();
        emit settingsClosed();
    });
    connect(trayButton_, &QPushButton::clicked, this, [this] { hide(); });
    connect(showPassButton_, &QPushButton::clicked, this, [this, muted] {
        passwordVisible_ = !passwordVisible_;
        passEdit_->setEchoMode(passwordVisible_ ? QLineEdit::Normal : QLineEdit::Password);
        showPassButton_->setIcon(button_icon(passwordVisible_ ? UiIcon::EyeOff : UiIcon::Eye, muted));
    });
    connect(downloadButton_, &QPushButton::clicked, this, [this] { emit downloadRequested(); });
    connect(stopZapretButton_, &QPushButton::clicked, this, [this] { emit stopZapretRequested(); });
    connect(minimizeCheck_, &QCheckBox::toggled, this, [this](bool on) {
        setMinimizeToTray(on);
        emit minimizeToTrayChanged(on);
    });
    connect(autoStartCheck_, &QCheckBox::toggled, this,
            [this](bool on) { emit autoStartChanged(on); });
    connect(autoZapretCheck_, &QCheckBox::toggled, this,
            [this](bool on) { emit autoRestoreZapretChanged(on); });
    connect(ipEdit_, &QLineEdit::textEdited, this, [this] { setHint(QString(), QStringLiteral("idle")); });
}

void MainWindow::applyStyle()
{
    root_->setStyleSheet(QStringLiteral(R"(
QWidget#root { background: #1c1c1c; }
QWidget#page { background: transparent; }
QLabel { background: transparent; color: #f3f3f3; }
QLabel#title { font-size: 20px; font-weight: 600; }
QLabel#muted { color: #9a9a9a; font-size: 12px; }
QLabel#rowText { color: #f3f3f3; font-size: 14px; }
QLabel#rowValue { color: #9a9a9a; font-size: 12px; }
QLabel#rowValue[state="ok"] { color: #10b981; }
QLabel#rowValue[state="error"] { color: #d94848; }
QLabel#hint { color: #9a9a9a; font-size: 12px; }
QLabel#hint[state="ok"] { color: #10b981; }
QLabel#hint[state="error"] { color: #d94848; }
QLabel#divider { background: #333333; }
QLabel#segmented { background: #262626; border: 1px solid #333333; border-radius: 8px; }
QLabel#statusPanel { background: #262626; border: 1px solid #333333; border-radius: 8px; }
QLabel#statusDot { background: #696969; border-radius: 4px; }
QLabel#statusDot[state="ok"] { background: #10b981; }
QLabel#statusDot[state="error"] { background: #d94848; }
QLabel#statusDot[state="busy"] { background: #9a9a9a; }
QLabel#statusText { color: #9a9a9a; font-size: 12px; }
QLabel#statusText[state="ok"] { color: #f3f3f3; }
QLabel#statusText[state="error"] { color: #d94848; }
QPushButton { background: transparent; border: 0; color: #d6d6d6; }
QPushButton#iconButton, QPushButton#iconButtonDanger { border-radius: 6px; }
QPushButton#iconButton:hover { background: #303030; color: #f3f3f3; }
QPushButton#iconButtonDanger:hover { background: #303030; }
QPushButton#modeButton { color: #9a9a9a; background: transparent; border-radius: 6px; font-size: 13px; }
QPushButton#modeButton:hover:!checked { background: #303030; }
QPushButton#modeButton:checked { color: #f3f3f3; background: #363636; border: 1px solid #444444; }
QPushButton#toggleButton { background: #10b981; color: #0c1410; border-radius: 6px; font-size: 14px; font-weight: 600; }
QPushButton#toggleButton:hover { background: #14c88c; }
QPushButton#toggleButton:pressed { background: #0e9f6e; }
QPushButton#toggleButton[connected="true"] { background: #d94848; color: #f3f3f3; }
QPushButton#toggleButton[connected="true"]:hover { background: #e25b5b; }
QPushButton#toggleButton:disabled { background: #333333; color: #9a9a9a; }
QLineEdit { background: #262626; border: 1px solid #333333; border-radius: 6px; color: #f3f3f3; padding: 0 8px; selection-background-color: #10b981; selection-color: #101010; }
QLineEdit:focus { border-color: #606060; }
QLineEdit:read-only { background: #212121; color: #b2b2b2; }
QCheckBox#switchCheck { background: transparent; color: #f3f3f3; font-size: 14px; spacing: 10px; }
QCheckBox#switchCheck::indicator { width: 40px; height: 20px; border-radius: 10px; background: #262626; border: 1px solid #9a9a9a; }
QCheckBox#switchCheck::indicator:checked { background: #4e4e4e; border: 1px solid #6a6a6a; }
QCheckBox#switchCheck:disabled { color: #9a9a9a; }
)"));
}

void MainWindow::repolish(QWidget* widget)
{
    if (!widget || !widget->style()) return;
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}

void MainWindow::showMain()
{
    settingsControls_->hide();
    mainControls_->show();
    root_->setGeometry(0, 0, 360, 400);
    setFixedSize(360, 400);
    setHint(QString(), QStringLiteral("idle"));
    refreshTelemetry();
}

void MainWindow::showSettings()
{
    mainControls_->hide();
    settingsControls_->show();
    root_->setGeometry(0, 0, 360, 468);
    setFixedSize(360, 468);
}

void MainWindow::showAndRaise()
{
    show();
    raise();
    activateWindow();
}

void MainWindow::setMode(Mode mode)
{
    mode_ = mode;
    modeProxyButton_->setChecked(mode == Mode::Proxy);
    modeTunButton_->setChecked(mode == Mode::Tun);
    refreshTelemetry();
}

void MainWindow::setConnected(bool connected)
{
    connected_ = connected;
    refreshControls();
    refreshTelemetry();
}

void MainWindow::setBusy(bool busy, const QString& text)
{
    busy_ = busy;
    if (busy && !text.isEmpty()) {
        statusOverride_ = text;
        statusError_ = false;
    } else if (!busy) {
        statusOverride_.clear();
        statusError_ = false;
    }
    refreshControls();
    refreshTelemetry();
}

void MainWindow::setStatus(const QString& text, bool error)
{
    statusOverride_ = text;
    statusError_ = error;
    refreshTelemetry();
}

void MainWindow::resetStatus()
{
    statusOverride_.clear();
    statusError_ = false;
    refreshTelemetry();
}

void MainWindow::setTelemetry(const QString& country, int pingMs, quint64 bytes,
                              bool connected, Mode mode)
{
    country_ = country;
    pingMs_ = pingMs;
    bytes_ = bytes;
    connected_ = connected;
    mode_ = mode;
    // Никаких таймеров и сетевых запросов здесь: только перерисовка,
    // и только когда окно действительно видно.
    refreshTelemetry();
}

void MainWindow::setLocalPort(int port)
{
    if (port > 0 && port <= 65535)
        localPortEdit_->setText(QString::number(port));
}

void MainWindow::setScanning(bool scanning)
{
    scanning_ = scanning;
    scanButton_->setIcon(button_icon(scanning ? UiIcon::Busy : UiIcon::Scan,
                                     QColor(QStringLiteral("#9a9a9a"))));
    if (scanning) setHint(QStringLiteral("Поиск..."), QStringLiteral("busy"));
    refreshControls();
}

void MainWindow::setTesting(bool testing)
{
    testing_ = testing;
    testButton_->setIcon(button_icon(testing ? UiIcon::Busy : UiIcon::Check,
                                     QColor(QStringLiteral("#9a9a9a"))));
    if (testing) setHint(QStringLiteral("Проверка..."), QStringLiteral("busy"));
    refreshControls();
}

void MainWindow::setScanResult(bool found, const QString& ip)
{
    if (found) ipEdit_->setText(ip);
    setHint(found ? QStringLiteral("Найден") : QStringLiteral("Не найден"),
            found ? QStringLiteral("ok") : QStringLiteral("error"));
    if (found) resetStatus();
}

void MainWindow::setTestResult(bool ok, const QString& hint)
{
    testButton_->setIcon(button_icon(ok ? UiIcon::Check : UiIcon::Cross,
                                     QColor(ok ? QStringLiteral("#10b981")
                                               : QStringLiteral("#d94848"))));
    setHint(hint, ok ? QStringLiteral("ok") : QStringLiteral("error"));
}

void MainWindow::setToggles(bool minimizeToTray, bool autoStart, bool autoRestoreZapret)
{
    const QSignalBlocker b1(minimizeCheck_);
    const QSignalBlocker b2(autoStartCheck_);
    const QSignalBlocker b3(autoZapretCheck_);
    minimizeCheck_->setChecked(minimizeToTray);
    autoStartCheck_->setChecked(autoStart);
    autoZapretCheck_->setChecked(autoRestoreZapret);
    setMinimizeToTray(minimizeToTray);
}

void MainWindow::setMinimizeToTray(bool enabled)
{
    minimizeToTray_ = enabled;
}

void MainWindow::setTunDriverInstalled(bool installed)
{
    driverValue_->setText(installed ? QStringLiteral("Установлен")
                                    : QStringLiteral("Не найден"));
    driverValue_->setProperty("state", installed ? QStringLiteral("ok")
                                                 : QStringLiteral("error"));
    repolish(driverValue_);
}

void MainWindow::setZapretActive(bool active)
{
    zapretValue_->setText(active ? QStringLiteral("Активен")
                                 : QStringLiteral("Остановлен"));
    zapretValue_->setProperty("state", active ? QStringLiteral("error")
                                              : QStringLiteral("idle"));
    repolish(zapretValue_);
    stopZapretButton_->setProperty("active", active);
    stopZapretButton_->setEnabled(active && !busy_);
    repolish(stopZapretButton_);
}

void MainWindow::setHint(const QString& text, const QString& state)
{
    ipHint_->setText(text);
    ipHint_->setProperty("state", state);
    repolish(ipHint_);
}

void MainWindow::refreshControls()
{
    const bool lock = connected_ || busy_;
    modeProxyButton_->setEnabled(!lock);
    modeTunButton_->setEnabled(!lock);
    scanButton_->setEnabled(!lock && !scanning_);
    testButton_->setEnabled(!busy_ && !testing_);
    downloadButton_->setEnabled(!lock);
    toggleButton_->setEnabled(!busy_);
    stopZapretButton_->setEnabled(!busy_ && stopZapretButton_->property("active").toBool());

    ipEdit_->setReadOnly(lock);
    socksPortEdit_->setReadOnly(lock);
    localPortEdit_->setReadOnly(lock);
    userEdit_->setReadOnly(lock);
    passEdit_->setReadOnly(lock);

    toggleButton_->setText(busy_ ? QStringLiteral("Подождите...")
                                 : (connected_ ? QStringLiteral("Отключить")
                                               : QStringLiteral("Подключить")));
    toggleButton_->setProperty("connected", connected_);
    repolish(toggleButton_);
}

void MainWindow::refreshTelemetry()
{
    if (!isVisible() || isMinimized()) return; // без фоновых обновлений в трее

    QString text;
    QString state = QStringLiteral("idle");
    if (busy_) {
        text = statusOverride_.isEmpty() ? QStringLiteral("Подключение...") : statusOverride_;
        state = QStringLiteral("busy");
    } else if (connected_) {
        const QString mb = QString::number(static_cast<double>(bytes_) / (1024.0 * 1024.0), 'f', 2);
        if (pingMs_ == -2) {
            text = QStringLiteral("Нет выхода в сеть через прокси · %1 МБ").arg(mb);
            state = QStringLiteral("error");
        } else if (!country_.isEmpty() && pingMs_ >= 0) {
            text = QStringLiteral("Подключено · %1 · %2 мс · %3 МБ")
                       .arg(country_).arg(pingMs_).arg(mb);
            state = QStringLiteral("ok");
        } else if (pingMs_ >= 0) {
            text = QStringLiteral("Подключено · %1 мс · %2 МБ").arg(pingMs_).arg(mb);
            state = QStringLiteral("ok");
        } else if (mode_ == Mode::Tun) {
            text = QStringLiteral("Подключено · TunBridge · %1 МБ").arg(mb);
            state = QStringLiteral("ok");
        } else {
            text = QStringLiteral("Подключено · 127.0.0.1:%1 · %2 МБ")
                       .arg(localPortEdit_->text()).arg(mb);
            state = QStringLiteral("ok");
        }
    } else if (!statusOverride_.isEmpty()) {
        text = statusOverride_;
        state = statusError_ ? QStringLiteral("error") : QStringLiteral("idle");
    } else {
        text = mode_ == Mode::Tun ? QStringLiteral("Отключено · Весь трафик (TUN)")
                                  : QStringLiteral("Отключено · Системный прокси");
    }

    statusDot_->setProperty("state", state);
    statusText_->setProperty("state", state);
    statusText_->setText(text);
    repolish(statusDot_);
    repolish(statusText_);
}

void MainWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    refreshTelemetry();
    emit visibilityChanged(true);
}

void MainWindow::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);
    emit visibilityChanged(false);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (minimizeToTray_) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

} // namespace tb
