#include "LaunchController.h"
#include <QDir>
#include <QFileInfo>
#include <QtConcurrentRun>
#include <windows.h>

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
        if (result.success) {
            succeededPid_ = loadingPid_;
            ownLaunchedProcess_ = false;
        }
        transition(result.success ? State::Succeeded : State::Failed,
                   result.success ? tr("Loaded successfully. Waiting for the game to open...")
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

static QString gameName(const QString &executable)
{
    const QString base = QFileInfo(executable).completeBaseName().trimmed();
    return base.isEmpty() ? QFileInfo(executable).fileName() : base;
}

void LaunchController::start(const QString &executable)
{
    if (state_ == State::Loading || state_ == State::Launching || worker_.isRunning() || state_ == State::Succeeded) return;
    stopOwnedProcess();
    succeededPid_ = 0;
    loadingPid_ = 0;
    timer_.stop();
    if (!authorizationExpiry_.isValid() || QDateTime::currentDateTimeUtc() >= authorizationExpiry_) {
        transition(State::Failed, tr("Your session has expired. Sign in again."));
        return;
    }
    const QString error = services_.validate(executable, payloadPath_);
    if (!error.isEmpty()) { transition(State::Failed, error); return; }
    executable_ = executable;
    cancelled_ = std::make_shared<std::atomic_bool>(false);
    const TargetProcess running = services_.find ? services_.find(executable_) : TargetProcess{};
    if (!running.error.isEmpty()) { transition(State::Failed, running.error); return; }
    if (running.pid != 0) {
        transition(State::Waiting, tr("%1 is already running. Watching for the right moment...").arg(gameName(executable_)));
        timer_.start();
        poll();
        return;
    }
    if (!services_.launch) {
        transition(State::Waiting, tr("Waiting for %1 to open...").arg(gameName(executable_)));
        timer_.start();
        poll();
        return;
    }
    transition(State::Launching, tr("Starting %1...").arg(gameName(executable_)));
    const TargetProcess launched = services_.launch(executable_);
    if (!launched.error.isEmpty() || launched.pid == 0) {
        transition(State::Failed, launched.error.isEmpty()
                   ? tr("Could not start %1.").arg(gameName(executable_)) : launched.error);
        return;
    }
    launchedPid_ = launched.pid;
    ownLaunchedProcess_ = true;
    transition(State::Waiting, tr("%1 is starting. Waiting for it to open...").arg(gameName(executable_)));
    timer_.start();
    poll();
}

void LaunchController::stopOwnedProcess()
{
    if (!ownLaunchedProcess_ || launchedPid_ == 0) return;
    ownLaunchedProcess_ = false;
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, launchedPid_);
    launchedPid_ = 0;
    if (!process) return;
    TerminateProcess(process, 0);
    CloseHandle(process);
}

void LaunchController::cancel()
{
    timer_.stop();
    cancelled_->store(true);
    if (state_ == State::Launching || state_ == State::Waiting || state_ == State::Loading) {
        stopOwnedProcess();
        transition(State::Cancelled, tr("Stopped. An operation already started cannot be undone."));
    }
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
    loadingPid_ = process.pid;
    transition(State::Loading, tr("Game found. Loading %1...").arg(QFileInfo(payloadPath_).fileName()));
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
