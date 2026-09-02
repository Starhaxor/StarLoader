# Task 7 Report — Verification and Activation Boundary

## Outcome

Added `docs/STARLOADER_PROTECTED_RELEASE.md` and linked it from the README.
They define a proof-ready, fail-closed activation boundary: production remains
blocked until KeyStar deploys the matching strict 600-second token profile and
server-side DPoP/replay validation. The client has no bearer-only protected
request fallback, refresh flow, or offline lease.

The activation guide documents no-secret CMake formats for the Ed25519 key
ring, exact KeyStar host, two distinct current/staged SPKI pins, and VMProtect
SDK include/library/project inputs. It also records the required deployment
order, protected-binary smoke tests, malware scan, Authenticode SHA-256
signing with RFC 3161 timestamp, signature verification, and the intentionally
narrow VMProtect marker regions and limitations.

## Verification

- `cmake --preset qt-mingw-local` configured successfully.
- `cmake --build --preset qt-mingw-local` built every target successfully.
- `ctest --preset qt-mingw-local --output-on-failure` passed 19/19 tests,
  including API, token, DPoP, TLS pinning, protected-release configuration,
  UI, and marker coverage.
- A production configure with `STARLOADER_TLS_SPKI_PINS=` failed as intended:
  it requires exactly two pins.
- A protected Release configure without VMProtect SDK inputs failed as
  intended: it requires an existing SDK include directory before proceeding.
- `git diff --check` was clean. A focused literal-secret scan found no access
  token, password, private-key, or proof-body literal in the checked paths.

## Live-flow boundary

The matching proof-enabled KeyStar fixture was not available in this
environment: `STARLOADER_NATIVE_LIVE_EMAIL`,
`STARLOADER_NATIVE_LIVE_PASSWORD`, and
`STARLOADER_NATIVE_LIVE_MAX_DEVICES` were unset. `NativeLiveFlowTest` therefore
skipped its native authentication flow. This is an explicit external
dependency, not evidence that a live production proof flow passed; the 19-test
unit/API/configuration suite remains the verified local coverage.

## Commit

`cc9ddb2` — `docs: define StarLoader protected-client activation`

## Review correction

The follow-up documentation review found legacy one-hour and bearer-only
statements in the README, an obsolete single-public-key configuration name,
runtime URL/HTTP override claims, and an imprecise protected-build preset.
This correction:

- makes every StarLoader protected-request description use the exact
  600-second profile, `Authorization: DPoP <access-token>`, and one TPM-signed
  `DPoP` proof, with no bearer-only fallback;
- replaces `STARLOADER_ED25519_PUBLIC_KEY` instructions with the exact
  `STARLOADER_ED25519_KEY_RING` syntax and links the required application,
  product, publishable-key, exact-host, and two-pin inputs;
- explains that `qt-mingw-local` selects the only local HTTP policy at CMake
  configuration time and that executables have no runtime URL/HTTP override;
- uses the exact protected build preset
  `qt-mingw-protected-build`, adds packaging only after Authenticode SHA-256
  signature verification, and documents a reproducible secret scan that does
  not exclude authored configuration files; and
- marks Tasks 1–6 complete from their commits/reports and re-marks Task 7 only
  after the corrected commands and checks below were rerun.

Correction verification on 2026-09-02:

- `cmake --list-presets`, `cmake --build --list-presets`, and
  `ctest --list-presets` confirmed `qt-mingw-protected-build` and the local
  configure/test preset names.
- `cmake --preset qt-mingw-local`, `cmake --build --preset qt-mingw-local`,
  and `ctest --preset qt-mingw-local --output-on-failure` completed; CTest
  passed 19/19.
- The documented literal-secret scan completed with no match, and
  `git diff --check` was clean.
- The native KeyStar proof fixture remained unavailable because its three
  `STARLOADER_NATIVE_LIVE_*` variables were unset; no live proof-flow pass is
  claimed.

Correction commit: `2e922f1` — `fix(docs): align protected release instructions`

## Final verification-script correction

The final branch review found that the developer launcher still selected local
HTTP through runtime environment variables, while the aggregate verification
script still configured the client with the obsolete single-public-key input
and injected a legacy bearer fixture. It also found that the documented inline
secret scan excluded authored tests and could echo matched secret contents.

The correction now:

- makes `run-client-dev.ps1` configure `qt-mingw-local`, build the canonical
  `qt-mingw-local-build` target, and launch only the resulting executable;
  it sets no runtime URL or HTTP-policy environment variable;
- makes `test-all.ps1` run the current local proof-bound configure/build/CTest
  presets, removes the legacy single-key/bearer smoke fixture and all embedded
  password/token literals, temporarily unsets the three native-live variables,
  and restores their exact prior process values in `finally`;
- retains the isolated PostgreSQL-backed Go regression suite without claiming
  it is a proof-enabled KeyStar live-flow fixture; and
- adds `scripts/scan-literal-secrets.ps1`, which scans authored code, tests,
  docs, configuration, and scripts while excluding only generated/build,
  vendored, Git, and nested-worktree paths. Its deterministic synthetic cases
  cover private-key PEM, compact tokens, authorization credentials, JSON and
  assignment forms, safe placeholders, and exclusions. Match diagnostics show
  paths only, never matched values.

Final correction verification on 2026-09-02:

- PowerShell parser checks passed for all three affected scripts.
- Secret-scanner synthetic coverage passed, and the real authored-tree scan
  found no prohibited literal or self-match.
- `cmake --preset qt-mingw-local` and
  `cmake --build --preset qt-mingw-local-build` completed successfully.
- `ctest --preset qt-mingw-local --output-on-failure` passed 19/19 tests.
- `NativeLiveFlowTest` was also invoked with all three native-live variables
  explicitly absent and exited successfully through its configured skip path;
  no live proof-enabled KeyStar pass is claimed.
- The aggregate `test-all.ps1` entry point could not complete its Docker-backed
  Go phase because Docker Desktop's Linux engine was not running. Its failure
  path was exercised with runtime-generated sentinel values, and all three
  native-live variables were restored byte-for-byte without being printed.
- `git diff --check` completed without whitespace errors.

Final correction commit subject: `fix(verification): align proof-bound client scripts`
