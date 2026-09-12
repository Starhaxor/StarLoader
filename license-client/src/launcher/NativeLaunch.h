#pragma once
#include "LaunchController.h"
LaunchServices nativeLaunchServices();
QString validateLaunchFiles(const QString &executable, const QString &payload);
