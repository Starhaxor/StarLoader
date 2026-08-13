#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QMainWindow>
#include <QPointer>
#include <memory>

QT_BEGIN_NAMESPACE
namespace Ui { class LoginWindow; }
QT_END_NAMESPACE
class ApiClient;
class AuthManager;
class IHardwareCollector;
class IDeviceSigner;
class UserDashboard;
class QMessageBox;
struct ApiError;
enum class AuthState;

class LoginWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit LoginWindow(QWidget *parent = nullptr);
    ~LoginWindow() override;

private:
    Ui::LoginWindow *ui;
    std::unique_ptr<IHardwareCollector> hardwareCollector_;
    std::unique_ptr<IDeviceSigner> deviceSigner_;
    ApiClient *apiClient_ = nullptr;
    AuthManager *authManager_ = nullptr;
    QPointer<UserDashboard> dashboard_;
    QPointer<QMessageBox> errorDialog_;
    void openHwidDialog();
    void startLogin();
    void showDashboard();
    void signOut();
    void applyState(AuthState state);
    static QString safeMessage(const ApiError &error);
    void showErrorDialog(const QString &code, const QString &text);

private slots:
    void showFailure(const ApiError &error);
};

#endif
