#pragma once

// Pure QtWidgets front-end. No QML / Quick / WebEngine, no custom paint loop:
// the whole screen is a fixed 360x400 (360x468 for settings) widget tree with
// object names styled by one dark QSS sheet.

#include "tunbridge/core.hpp"

#include <QIcon>
#include <QString>
#include <QWidget>

class QCheckBox;
class QCloseEvent;
class QHideEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;

namespace tb {

class MainWindow : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    QString ip() const;
    int socksPort() const;
    int localPort() const;
    QString user() const;
    QString password() const;

signals:
    void modeChanged(Mode mode);
    void connectRequested();
    void scanRequested();
    void testRequested();
    void settingsClosed();
    void minimizeToTrayChanged(bool enabled);
    void autoStartChanged(bool enabled);
    void autoRestoreZapretChanged(bool enabled);
    void downloadRequested();
    void stopZapretRequested();
    void visibilityChanged(bool visible);

public slots:
    void showMain();
    void showSettings();
    void showAndRaise();

    void setMode(Mode mode);
    void setConnected(bool connected);
    void setBusy(bool busy, const QString& text = QString());
    void setStatus(const QString& text, bool error = false);
    void resetStatus();
    void setTelemetry(const QString& country, int pingMs, quint64 bytes,
                      bool connected, Mode mode);
    void setLocalPort(int port);
    void setScanning(bool scanning);
    void setTesting(bool testing);
    void setScanResult(bool found, const QString& ip);
    void setTestResult(bool ok, const QString& hint);
    void setToggles(bool minimizeToTray, bool autoStart, bool autoRestoreZapret);
    void setMinimizeToTray(bool enabled);
    void setTunDriverInstalled(bool installed);
    void setZapretActive(bool active);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi();
    void applyStyle();
    void refreshTelemetry();
    void refreshControls();
    void setHint(const QString& text, const QString& state);
    static void repolish(QWidget* widget);

    Mode mode_{Mode::Proxy};
    bool connected_{false};
    bool busy_{false};
    bool scanning_{false};
    bool testing_{false};
    bool minimizeToTray_{true};
    bool passwordVisible_{false};
    int pingMs_{-1};
    quint64 bytes_{0};
    QString country_;
    QString statusOverride_;
    bool statusError_{false};

    QWidget* root_{nullptr};
    QLabel* titleLabel_{nullptr};
    QLabel* divider_{nullptr};
    QLabel* divider2_{nullptr};
    QLabel* ipCaption_{nullptr};
    QLabel* ipHint_{nullptr};
    QLabel* statusPanel_{nullptr};
    QLabel* statusDot_{nullptr};
    QLabel* statusText_{nullptr};
    QLabel* socksCaption_{nullptr};
    QLabel* localCaption_{nullptr};
    QLabel* userCaption_{nullptr};
    QLabel* passCaption_{nullptr};
    QLabel* driverCaption_{nullptr};
    QLabel* driverValue_{nullptr};
    QLabel* zapretCaption_{nullptr};
    QLabel* zapretValue_{nullptr};
    QLineEdit* ipEdit_{nullptr};
    QLineEdit* socksPortEdit_{nullptr};
    QLineEdit* localPortEdit_{nullptr};
    QLineEdit* userEdit_{nullptr};
    QLineEdit* passEdit_{nullptr};
    QPushButton* trayButton_{nullptr};
    QPushButton* settingsButton_{nullptr};
    QPushButton* backButton_{nullptr};
    QPushButton* modeProxyButton_{nullptr};
    QPushButton* modeTunButton_{nullptr};
    QPushButton* scanButton_{nullptr};
    QPushButton* testButton_{nullptr};
    QPushButton* toggleButton_{nullptr};
    QPushButton* showPassButton_{nullptr};
    QPushButton* downloadButton_{nullptr};
    QPushButton* stopZapretButton_{nullptr};
    QCheckBox* minimizeCheck_{nullptr};
    QCheckBox* autoStartCheck_{nullptr};
    QCheckBox* autoZapretCheck_{nullptr};

    QWidget* mainControls_{nullptr};
    QWidget* settingsControls_{nullptr};
};

} // namespace tb
