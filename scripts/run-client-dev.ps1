# Development launcher for the StarLoader desktop client against the local
# API container. The client refuses plain HTTP unless the host is a loopback
# IP and STARLOADER_ALLOW_HTTP_LOCAL=1 (localhost name is rejected by design).
$repoRoot = Split-Path -Parent $PSScriptRoot
$env:STARLOADER_API_URL = 'http://127.0.0.1:8080'
$env:STARLOADER_ALLOW_HTTP_LOCAL = '1'
& (Join-Path $repoRoot 'build\license-client\LicenseClient.exe')
