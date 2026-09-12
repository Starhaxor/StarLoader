# Fixed-module game connection

After authentication, StarLoader shows a compact 560-by-330 window with an
account/license summary above a single game card. Hardware identifiers, device
limits, and session timestamps are omitted. The user selects a game executable;
there is no DLL picker or persistent DLL information panel.
The only payload path is `AssaultCubeMultiHack.dll` beside `LicenseClient.exe`,
resolved from the application directory rather than the shell's working directory.
The DLL is supplied separately and is not included in source control.

## Behavior

1. Require an active account/license/device profile and an unexpired session/license.
2. Check the selected EXE and fixed DLL exist, have supported PE headers, and
   agree on x86/x64 architecture.
3. Poll for the selected executable's full canonical path. A process with only
   the same filename in a different directory is not a match. Multiple matching
   processes are an error.
4. Perform one asynchronous manual-map attempt for the matching process. The
   UI remains responsive; there are no alternative injection methods or retries
   against the same process.
5. Close the dashboard 900 ms after a confirmed successful result. Failure,
   timeout, or cancellation does not emit completion. After a failed attempt,
   restart the game before retrying.

Stop waiting, sign-out, window closure, or session expiry cancels pending work.
An already-started native operation cannot be rolled back; its late completion
is ignored after cancellation. Minimize does not deliberately cancel waiting.
Remote calls that time out retain memory still potentially in use; restarting
the test process is required after an incomplete attempt.

## Source and scope

`license-client/src/launcher/StarInjectorManualMap.cpp` is adapted from the
user's local `StarInjector/injectorengine.cpp`. It includes the manual-map path
and its dependencies, removes the alternate thread-creation fallback, narrows
process access, checks remote-call completion, and rejects a failed DLL entry
point instead of reporting a successful load unconditionally. Completion
conservatively requires an explicit TRUE result and a still-running target;
abnormal thread termination codes are rejected.

The integration is intended for the user's local AssaultCube test environment.
It does not establish compatibility with arbitrary games or DLLs. Existing
mapper limitations still require real target testing. There is no driver,
anti-cheat bypass, or concealment configuration in this panel.

## Validation

`LaunchControllerTest` covers missing/invalid/mismatched files, waiting, fixed
payload selection, one attempt per process, cancellation, expiry, late results,
and native full-path process lookup. `UserDashboardTest` covers the compact
layout, existing account behavior, absence of a DLL picker, and completion closure.

The tests simulate the mapping result; they do not execute the supplied DLL.
Keep the existing native authentication/live fixture checks and real-game
smoke tests separate. Local-development builds retain the existing loopback
KeyStar fixture configuration and are not production release packages.
