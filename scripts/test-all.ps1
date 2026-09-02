[CmdletBinding()]
param(
    [int]$PostgresPort = 55434
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$databaseContainer = 'starloader-verification-db'
$databasePassword = [guid]::NewGuid().ToString('N')
$databaseURL = "postgres://starloader:$databasePassword@host.docker.internal:$PostgresPort/starloader_test?sslmode=disable"
$cmake = 'C:\Qt\Tools\CMake_64\bin\cmake.exe'
$ctest = 'C:\Qt\Tools\CMake_64\bin\ctest.exe'
$literalSecretScanner = Join-Path $PSScriptRoot 'scan-literal-secrets.ps1'
$nativeLiveVariables = @(
    'STARLOADER_NATIVE_LIVE_EMAIL',
    'STARLOADER_NATIVE_LIVE_PASSWORD',
    'STARLOADER_NATIVE_LIVE_MAX_DEVICES'
)
$savedNativeLiveVariables = @{}

function Invoke-Checked {
    if ($args.Count -eq 0) {
        throw 'Invoke-Checked requires a program.'
    }
    $program = $args[0]
    $programArguments = @($args | Select-Object -Skip 1)
    & $program @programArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

function Remove-VerificationContainer {
    param([string]$Name)
    $containerId = & docker ps -aq --filter "name=^/${Name}$"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect Docker verification containers.'
    }
    if ($containerId) {
        Invoke-Checked docker rm -f $Name | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $cmake) -or -not (Test-Path -LiteralPath $ctest)) {
    throw 'Qt CMake/CTest was not found under C:\Qt.'
}
if (-not (Test-Path -LiteralPath $literalSecretScanner)) {
    throw 'Literal-secret scanner is missing.'
}

Push-Location $repoRoot
try {
    foreach ($name in $nativeLiveVariables) {
        $existing = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $existing) {
            $savedNativeLiveVariables[$name] = $existing
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    }
    Remove-VerificationContainer -Name $databaseContainer
    Invoke-Checked docker run -d --name $databaseContainer `
        -e POSTGRES_DB=starloader_test `
        -e POSTGRES_USER=starloader `
        -e POSTGRES_PASSWORD=$databasePassword `
        -p "127.0.0.1:${PostgresPort}:5432" `
        postgres:17-alpine

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $databaseContainer pg_isready -U starloader -d starloader_test 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw 'PostgreSQL verification container did not become ready.'
    }

    Invoke-Checked docker run --rm --add-host host.docker.internal:host-gateway `
        -e "TEST_DATABASE_URL=$databaseURL" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go test -race ./... -count=1

    Invoke-Checked docker run --rm -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go vet ./...

    Invoke-Checked $cmake --preset qt-mingw-local
    Invoke-Checked $cmake --build --preset qt-mingw-local-build
    Invoke-Checked $ctest --preset qt-mingw-local --output-on-failure

    & $literalSecretScanner -SelfTest
    & $literalSecretScanner
    Invoke-Checked git diff --check
    Write-Host 'Backend regression tests and the local proof-bound client suite passed.'
    Write-Host 'The live proof-enabled KeyStar flow was intentionally not run by this script.'
}
finally {
    foreach ($name in $nativeLiveVariables) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        if ($savedNativeLiveVariables.ContainsKey($name)) {
            Set-Item "Env:$name" $savedNativeLiveVariables[$name]
        }
    }
    Pop-Location
    Remove-VerificationContainer -Name $databaseContainer
}
