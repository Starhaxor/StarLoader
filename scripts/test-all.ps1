[CmdletBinding()]
param(
    [int]$PostgresPort = 55434
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$databaseContainer = 'starloader-verification-db'
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
    $containerId = & docker ps -aq --filter "name=^/${databaseContainer}$"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect Docker verification containers.'
    }
    if ($containerId) {
        Invoke-Checked docker rm -f $databaseContainer | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $cmake) -or -not (Test-Path -LiteralPath $ctest)) {
    throw 'Qt CMake/CTest was not found under C:\Qt.'
}

Push-Location $repoRoot
try {
    Remove-VerificationContainer
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
        golang:1.24 go run ./cmd/server admin create-license --user verification@example.com --product StarLoader --days 1 --max-devices 1
    if ($LASTEXITCODE -ne 0 -or $licenseOutput -notmatch '^[0-9A-F]{8}(?:-[0-9A-F]{8}){3}$') {
        throw 'Administrative license creation failed.'
    }

    $env:Path = "C:\Qt\Tools\mingw1310_64\bin;C:\Qt\6.11.1\mingw_64\bin;C:\Qt\Tools\Ninja;C:\Qt\Tools\mingw1310_64\opt\bin;$env:Path"
    Invoke-Checked $cmake -S $repoRoot -B $buildDirectory -G Ninja `
        "-DCMAKE_PREFIX_PATH=$qtRoot" `
        "-DOPENSSL_ROOT_DIR=$opensslRoot" `
        "-DSTARLOADER_ED25519_PUBLIC_KEY=$publicKey"
    Invoke-Checked $cmake --build $buildDirectory
    Invoke-Checked $ctest --test-dir $buildDirectory --output-on-failure

    Invoke-Checked git diff --check
    Write-Host 'All StarLoader verification checks passed.'
}
finally {
    Pop-Location
    Remove-VerificationContainer
}
