#pragma once

#include <QDateTime>
#include <QFutureWatcher>
#include <QObject>
#include <QSet>
#include <QTimer>
#include <atomic>
#include <functional>
#include <memory>

struct TargetProcess { quint32 pid = 0; QString error; };
struct LaunchResult { bool success = false; QString error; };
struct LaunchServices {
    std::function<QString(const QString &, const QString &)> validate;
    std::function<TargetProcess(const QString &)> find;
    std::function<LaunchResult(quint32, const QString &, const QString &)> load;
    // Starts the game and returns its pid. Empty (e.g. in tests) means the
    // user starts the game manually and the controller only watches for it.
    std::function<TargetProcess(const QString &)> launch;
};

class LaunchController final : public QObject {
    Q_OBJECT
public:
    enum class State { Ready, Launching, Waiting, Loading, Succeeded, Failed, Cancelled };
    Q_ENUM(State)
    LaunchController(QString applicationDirectory, QDateTime authorizationExpiry,
                     LaunchServices services, QObject *parent = nullptr);
    ~LaunchController() override;
    State state() const { return state_; }
    QString payloadPath() const { return payloadPath_; }
    QString message() const { return message_; }
    quint32 succeededPid() const { return succeededPid_; }
    void start(const QString &executable);
    void cancel();
signals:
    void changed();
    void completed();
private:
    void poll();
    void transition(State state, const QString &message);
    void stopOwnedProcess();
    QString payloadPath_, executable_, message_;
    quint32 succeededPid_ = 0;
    quint32 loadingPid_ = 0;
    quint32 launchedPid_ = 0;
    bool ownLaunchedProcess_ = false;
    QDateTime authorizationExpiry_;
    LaunchServices services_;
    State state_ = State::Ready;
    QTimer timer_;
    QFutureWatcher<LaunchResult> worker_;
    QSet<quint32> attemptedProcesses_;
    std::shared_ptr<std::atomic_bool> cancelled_;
};
