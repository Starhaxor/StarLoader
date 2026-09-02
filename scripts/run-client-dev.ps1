# Development launcher for the StarLoader desktop client against the local API
# container. The loopback exception is selected at CMake configuration time by
# qt-mingw-local; this script has no runtime URL or HTTP override.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$clientExecutable = Join-Path $repoRoot 'build\license-client\LicenseClient.exe'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Program,
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$ProgramArguments
    )

    & $Program @ProgramArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE."
    }
}

Push-Location $repoRoot
try {
    Invoke-Checked cmake --preset qt-mingw-local
    Invoke-Checked cmake --build --preset qt-mingw-local-build --target LicenseClient
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $clientExecutable -PathType Leaf)) {
    throw 'LicenseClient executable was not produced by the local build.'
}
& $clientExecutable
