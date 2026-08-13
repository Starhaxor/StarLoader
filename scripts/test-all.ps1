[CmdletBinding()]
param(
    [int]$PostgresPort = 55434,
    [int]$ApiPort = 58080
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$databaseContainer = 'starloader-verification-db'
$apiContainer = 'starloader-verification-api'
$databasePassword = 'starloader-verification-password'
$databaseURL = "postgres://starloader:$databasePassword@host.docker.internal:$PostgresPort/starloader_test?sslmode=disable"
$qtRoot = 'C:\Qt\6.11.1\mingw_64'
$cmake = 'C:\Qt\Tools\CMake_64\bin\cmake.exe'
$ctest = 'C:\Qt\Tools\CMake_64\bin\ctest.exe'
$opensslRoot = 'C:\Qt\Tools\mingw1310_64\opt'
$buildDirectory = Join-Path $repoRoot 'build-verification'

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

Push-Location $repoRoot
try {
    Remove-VerificationContainer -Name $apiContainer
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

    $generatedKeys = & docker run --rm -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server keygen
    if ($LASTEXITCODE -ne 0) {
        throw 'Signing-key generation failed.'
    }
    $publicKeyLine = $generatedKeys | Where-Object { $_ -like 'STARLOADER_ED25519_PUBLIC_KEY=*' } | Select-Object -First 1
    $privateKeyLine = $generatedKeys | Where-Object { $_ -like 'ED25519_PRIVATE_KEY=*' } | Select-Object -First 1
    if (-not $publicKeyLine -or -not $privateKeyLine) {
        throw 'Generated signing keys were not returned.'
    }
    $publicKey = $publicKeyLine.Substring('STARLOADER_ED25519_PUBLIC_KEY='.Length)
    $privateKey = $privateKeyLine.Substring('ED25519_PRIVATE_KEY='.Length)

    Invoke-Checked docker run --rm --add-host host.docker.internal:host-gateway `
        -e "DATABASE_URL=$databaseURL" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server migrate down
    Invoke-Checked docker run --rm --add-host host.docker.internal:host-gateway `
        -e "DATABASE_URL=$databaseURL" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server migrate up

    "verification-password`nverification-password" | & docker run --rm -i --add-host host.docker.internal:host-gateway `
        -e "DATABASE_URL=$databaseURL" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server admin create-user --email verification@example.com --password-stdin
    if ($LASTEXITCODE -ne 0) {
        throw 'Administrative user creation failed.'
    }
    $licenseOutput = & docker run --rm --add-host host.docker.internal:host-gateway `
        -e "DATABASE_URL=$databaseURL" -e LICENSE_HMAC_KEY=verification-license-hmac-key `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server admin create-license --user verification@example.com --product StarLoader --days 1 --max-devices 2
    if ($LASTEXITCODE -ne 0 -or $licenseOutput -notmatch '^[0-9A-F]{8}(?:-[0-9A-F]{8}){3}$') {
        throw 'Administrative license creation failed.'
    }
    $licenseKey = ([string]$licenseOutput).Trim()

    Invoke-Checked docker run -d --name $apiContainer --add-host host.docker.internal:host-gateway `
        -e "DATABASE_URL=$databaseURL" `
        -e LICENSE_HMAC_KEY=verification-license-hmac-key `
        -e HARDWARE_HMAC_KEY=verification-hardware-hmac-key `
        -e "ED25519_PRIVATE_KEY=$privateKey" `
        -e LICENSE_ISSUER=starloader -e LICENSE_AUDIENCE=starloader-client `
        -e PRODUCT=StarLoader -e SERVER_ADDR=:8080 `
        -p "127.0.0.1:${ApiPort}:8080" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go run ./cmd/server serve

    $apiReady = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:${ApiPort}/healthz" -TimeoutSec 1
            if ($health.StatusCode -eq 200) {
                $apiReady = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $apiReady) {
        & docker logs $apiContainer
        throw 'Production server verification container did not become ready.'
    }

    Invoke-Checked docker run --rm --add-host host.docker.internal:host-gateway `
        -e "STARLOADER_SMOKE_BASE_URL=http://host.docker.internal:${ApiPort}" `
        -e STARLOADER_SMOKE_EMAIL=verification@example.com `
        -e STARLOADER_SMOKE_PASSWORD=verification-password `
        -e STARLOADER_SMOKE_MAX_DEVICES=2 `
        -e "STARLOADER_SMOKE_LICENSE=$licenseKey" `
        -e "STARLOADER_SMOKE_ED25519_PUBLIC_KEY=$publicKey" `
        -e "STARLOADER_SMOKE_ED25519_PRIVATE_KEY=$privateKey" `
        -v "${repoRoot}:/workspace" -w /workspace/backend `
        golang:1.24 go test ./tests/blackbox -run TestProductionServerLoginDeviceAndReplay -count=1 -v

    $env:Path = "C:\Qt\Tools\mingw1310_64\bin;C:\Qt\6.11.1\mingw_64\bin;C:\Qt\Tools\Ninja;C:\Qt\Tools\mingw1310_64\opt\bin;$env:Path"
    Invoke-Checked $cmake -S $repoRoot -B $buildDirectory -G Ninja `
        "-DCMAKE_PREFIX_PATH=$qtRoot" `
        "-DOPENSSL_ROOT_DIR=$opensslRoot" `
        "-DSTARLOADER_ED25519_PUBLIC_KEY=$publicKey"
    Invoke-Checked $cmake --build $buildDirectory
    $env:STARLOADER_API_URL = "http://127.0.0.1:${ApiPort}"
    $env:STARLOADER_ALLOW_HTTP_LOCAL = '1'
    $env:STARLOADER_NATIVE_LIVE_EMAIL = 'verification@example.com'
    $env:STARLOADER_NATIVE_LIVE_PASSWORD = 'verification-password'
    $env:STARLOADER_NATIVE_LIVE_MAX_DEVICES = '2'
    Invoke-Checked $ctest --test-dir $buildDirectory --output-on-failure

    Invoke-Checked git diff --check
    Write-Host 'All StarLoader verification checks passed.'
}
finally {
    Remove-Item Env:STARLOADER_API_URL,Env:STARLOADER_ALLOW_HTTP_LOCAL,Env:STARLOADER_NATIVE_LIVE_EMAIL,Env:STARLOADER_NATIVE_LIVE_PASSWORD,Env:STARLOADER_NATIVE_LIVE_MAX_DEVICES -ErrorAction SilentlyContinue
    Pop-Location
    Remove-VerificationContainer -Name $apiContainer
    Remove-VerificationContainer -Name $databaseContainer
}
