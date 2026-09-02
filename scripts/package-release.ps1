[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ProtectedExecutable,
    [Parameter(Mandatory = $true)] [string] $ProtectedOutputRoot,
    [Parameter(Mandatory = $true)] [string] $DestinationRoot,
    [Parameter(Mandatory = $true)] [string] $SignToolPath,
    [Parameter(Mandatory = $true)] [string] $WindowsDefenderCommand
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ExistingAbsolutePath([string] $Path, [string] $Name) {
    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) { throw "$Name must be an absolute path." }
    if (-not (Test-Path -LiteralPath $Path)) { throw "$Name does not exist." }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Test-IsWithin([string] $Candidate, [string] $Root) {
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $normalizedRoot = $Root.TrimEnd($separator) + $separator
    return $Candidate.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$executablePath = Resolve-ExistingAbsolutePath $ProtectedExecutable 'ProtectedExecutable'
$protectedRootPath = Resolve-ExistingAbsolutePath $ProtectedOutputRoot 'ProtectedOutputRoot'
$signTool = Resolve-ExistingAbsolutePath $SignToolPath 'SignToolPath'
$defender = Resolve-ExistingAbsolutePath $WindowsDefenderCommand 'WindowsDefenderCommand'

if ([System.IO.Path]::GetExtension($executablePath) -ine '.exe') { throw 'ProtectedExecutable must be an executable file.' }
if (-not (Test-IsWithin $executablePath $protectedRootPath)) { throw 'ProtectedExecutable must be inside ProtectedOutputRoot.' }

$ordinaryBuild = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'build'))
$separator = [System.IO.Path]::DirectorySeparatorChar
$nestedBuildMarker = "${separator}build${separator}"
if ((Test-IsWithin $executablePath $ordinaryBuild) -or
    $executablePath.Contains($nestedBuildMarker, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Ordinary shared build output cannot be packaged as a protected release.'
}

if (-not [System.IO.Path]::IsPathFullyQualified($DestinationRoot)) { throw 'DestinationRoot must be an absolute path.' }
$destinationPath = [System.IO.Path]::GetFullPath($DestinationRoot)
if (Test-Path -LiteralPath $destinationPath) { throw 'DestinationRoot must be a fresh path that does not already exist.' }
if ((Test-IsWithin $destinationPath $ordinaryBuild) -or (Test-IsWithin $destinationPath $protectedRootPath)) {
    throw 'DestinationRoot must be separate from build and protected-output roots.'
}

$sourceHash = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash
New-Item -ItemType Directory -Path $destinationPath | Out-Null
$stagedExecutable = Join-Path $destinationPath ([System.IO.Path]::GetFileName($executablePath))

try {
    Copy-Item -LiteralPath $executablePath -Destination $stagedExecutable
    $stagedHash = (Get-FileHash -LiteralPath $stagedExecutable -Algorithm SHA256).Hash
    if ($sourceHash -cne $stagedHash) { throw 'Staged executable hash does not match the selected protected executable.' }

    $signature = Get-AuthenticodeSignature -LiteralPath $stagedExecutable
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw 'Authenticode signature or RFC 3161 timestamp is not valid.'
    }

    $verificationOutput = & $signTool verify /pa /all /v $stagedExecutable 2>&1
    if ($LASTEXITCODE -ne 0 -or
        -not (($verificationOutput -join "`n") -match '(?i)successfully verified') -or
        -not (($verificationOutput -join "`n") -match '(?i)(sha-?256)') -or
        -not (($verificationOutput -join "`n") -match '(?i)timestamp')) {
        throw 'SignTool could not verify the SHA-256 Authenticode signature and timestamp.'
    }

    & $defender -Scan -ScanType 3 -File $stagedExecutable -DisableRemediation | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows Defender did not complete a clean scan of the staged executable.' }
} catch {
    $failure = $_
    try {
        Set-Content -LiteralPath (Join-Path $destinationPath 'NON_DISTRIBUTABLE.txt') `
            -Value 'A required release gate failed. Do not distribute any file from this directory.' `
            -Encoding UTF8
    } catch {
        # Preserve the original fail-closed gate error even if marking fails.
    }
    throw $failure
}

Write-Host "Staged protected executable passed the configured final gates: $stagedExecutable"
Write-Host 'This is not a ready-to-distribute package. Runtime dependencies, protected smoke tests, dependency scanning, and final archive verification remain required.'
