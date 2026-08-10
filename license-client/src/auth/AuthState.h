#pragma once

enum class AuthState { LoggedOut, CollectingDevice, Authenticating, WaitingForDeviceChallenge, VerifyingDevice, Authenticated, Failed };
Q_DECLARE_METATYPE(AuthState)
