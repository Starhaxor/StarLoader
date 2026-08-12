#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QMainWindow>
#include <memory>

QT_BEGIN_NAMESPACE
namespace Ui { class LoginWindow; }
QT_END_NAMESPACE
class ApiClient;
class AuthManager;
class IHardwareCollector;
class IDeviceSigner;
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
    void openHwidDialog();
    void startLogin();
    void applyState(AuthState state);
    void showFailure(const ApiError &error);
    static QString safeMessage(const ApiError &error);
};

#endif
