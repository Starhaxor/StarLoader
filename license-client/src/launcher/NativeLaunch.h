#pragma once
#include "LaunchController.h"
#include <QtTypes>
LaunchServices nativeLaunchServices();
QString validateLaunchFiles(const QString &executable, const QString &payload);
// True while a process with this pid is still running.
bool processAlive(quint32 pid);
// True when the process owns at least one visible top-level window.
bool processWindowOpen(quint32 pid);
// Starts the game executable in its own folder and returns its pid.
TargetProcess launchGame(const QString &executable);
