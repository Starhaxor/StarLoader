#include "LaunchController.h"
#include <QDir>
#include <QtConcurrentRun>

LaunchController::LaunchController(QString directory, QDateTime expiry, LaunchServices services, QObject *parent)
    : QObject(parent), payloadPath_(QDir(directory).absoluteFilePath(QStringLiteral("AssaultCubeMultiHack.dll"))),
      authorizationExpiry_(expiry), services_(std::move(services)),
      cancelled_(std::make_shared<std::atomic_bool>(false))
{
    timer_.setInterval(500);
    connect(&timer_, &QTimer::timeout, this, &LaunchController::poll);
    connect(&worker_, &QFutureWatcher<LaunchResult>::finished, this, [this] {
        if (state_ != State::Loading || cancelled_->load()) return;
        if (QDateTime::currentDateTimeUtc() >= authorizationExpiry_) { cancel(); return; }
        timer_.stop();
        const LaunchResult result = worker_.result();
        transition(result.success ? State::Succeeded : State::Failed,
                   result.success ? tr("Loaded successfully. Closing StarLoader...")
                                  : result.error + tr(" Restart the game before trying again."));
        if (result.success) emit completed();
    });
    message_ = tr("Select the game executable to begin.");
}

LaunchController::~LaunchController() { cancel(); }

void LaunchController::transition(State state, const QString &message)
{
    state_ = state;
    message_ = message;
    emit changed();
}

void LaunchController::start(const QString &executable)
{
    if (state_ == State::Loading || worker_.isRunning() || state_ == State::Succeeded) return;
    timer_.stop();
    if (!authorizationExpiry_.isValid() || QDateTime::currentDateTimeUtc() >= authorizationExpiry_) {
        transition(State::Failed, tr("Your session has expired. Sign in again."));
        return;
    }
    const QString error = services_.validate(executable, payloadPath_);
    if (!error.isEmpty()) { transition(State::Failed, error); return; }
    executable_ = executable;
    cancelled_ = std::make_shared<std::atomic_bool>(false);
    transition(State::Waiting, tr("Waiting for the selected game to open..."));
    timer_.start();
    poll();
}

void LaunchController::cancel()
{
    timer_.stop();
    cancelled_->store(true);
    if (state_ == State::Waiting || state_ == State::Loading)
        transition(State::Cancelled, tr("Stopped. An operation already started cannot be undone."));
}

void LaunchController::poll()
{
    if (QDateTime::currentDateTimeUtc() >= authorizationExpiry_) { cancel(); return; }
    if (state_ != State::Waiting) return;
    const TargetProcess process = services_.find(executable_);
    if (!process.error.isEmpty()) { timer_.stop(); transition(State::Failed, process.error); return; }
    if (process.pid == 0) return;
    if (attemptedProcesses_.contains(process.pid)) {
        timer_.stop();
        transition(State::Failed, tr("This process was already attempted. Restart the game first."));
        return;
    }
    attemptedProcesses_.insert(process.pid);
    transition(State::Loading, tr("Game found. Loading AssaultCubeMultiHack.dll..."));
    const auto load = services_.load;
    const auto cancelled = cancelled_;
    const auto expiry = authorizationExpiry_;
    const QString executable = executable_, payload = payloadPath_;
    worker_.setFuture(QtConcurrent::run([load, cancelled, expiry, executable, payload, pid = process.pid] {
        if (cancelled->load() || QDateTime::currentDateTimeUtc() >= expiry)
            return LaunchResult{false, QStringLiteral("Session ended before loading.")};
        try {
            return load(pid, executable, payload);
        } catch (...) {
            return LaunchResult{false, QStringLiteral("The loading operation failed unexpectedly.")};
        }
    }));
}
