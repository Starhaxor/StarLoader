[CmdletBinding()]
param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot

# Assemble signatures so this scanner's own source does not contain a complete
# prohibited literal. Matches are reported by path only; secret contents never
# enter diagnostics.
$pemPattern = '-----' + 'BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY)-----'
$jwtPattern = '\b' + 'eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b'
$authorizationPattern = 'Authorization:\s*' + '(?:Bearer|DPoP)\s+[A-Za-z0-9._~-]{20,}'
$jsonCredentialPattern = '"(?:password|access_token|refresh_token|dpop)"\s*:\s*"(?!\s*(?:<|\$\{|example-|test-|verification-|replace-with-))[^"\r\n+`]{15,}"'
$environmentNames = '(?:ED25519_PRIVATE_KEY|PASSWORD|ACCESS_TOKEN|REFRESH_TOKEN|DPOP)'
$environmentAssignmentPattern = '(?m)^\s*(?:export\s+)?' + $environmentNames + '\s*=\s*["'']?(?!\s*(?:\$|<|example-|test-|verification-|replace-with-|["'']?\s*(?:$|#)))[^\r\n#"'']{15,}'
$powershellAssignmentPattern = '(?im)^\s*\$[A-Za-z0-9_]*(?:password|accessToken|refreshToken|privateKey|dpop)[A-Za-z0-9_]*\s*=\s*["''](?!\s*(?:\$|<|example-|test-|verification-|replace-with-))[^"'']{15,}["'']'
$patterns = @(
    $pemPattern,
    $jwtPattern,
    $authorizationPattern,
    $jsonCredentialPattern,
    $environmentAssignmentPattern,
    $powershellAssignmentPattern
)
$excludedGlobs = @(
    '!.git', '!.git/**', '!**/.git/**',
    '!.worktrees', '!.worktrees/**', '!**/.worktrees/**',
    '!build/**', '!build-*/**', '!**/build/**', '!**/build-*/**',
    '!**/generated/**', '!**/vendor/**', '!**/third_party/**'
)

function Invoke-LiteralSecretScan {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string[]]$SearchPatterns,
        [string[]]$Globs = @()
    )

    # Windows PowerShell 5 rewrites quotes in native-process arguments. Several
    # PCRE patterns intentionally contain quote characters, so passing them via
    # repeated -e arguments can make the following path look like a regex.
    # A pattern file preserves every character exactly across PowerShell hosts.
    $patternFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllLines($patternFile, $SearchPatterns, [System.Text.UTF8Encoding]::new($false))
        $arguments = @('--hidden', '--no-ignore', '--files-with-matches', '--pcre2', '-i', "--file=$patternFile")
        foreach ($glob in $Globs) {
            $arguments += "--glob=$glob"
        }
        $arguments += $Path

        $matchedPaths = @(& rg @arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    finally {
        Remove-Item -LiteralPath $patternFile -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -gt 1) {
        throw "Literal-secret scan failed with exit code $exitCode."
    }
    return [PSCustomObject]@{
        Found = $exitCode -eq 0
        Paths = $matchedPaths
    }
}

function Assert-SyntheticCoverage {
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $tempDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $tempRoot ('starloader-secret-scan-' + [guid]::NewGuid().ToString('N')))
    )
    if (-not $tempDirectory.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Literal-secret scanner self-test directory escaped the system temporary directory.'
    }
    New-Item -ItemType Directory -Path $tempDirectory | Out-Null
    try {
        $begin = '-----' + 'BEGIN '
        $end = '-----'
        $privateKeyName = 'ED25519_' + 'PRIVATE_KEY'
        $passwordName = 'PASS' + 'WORD'
        $accessTokenName = 'ACCESS_' + 'TOKEN'
        $jwt = 'eyJ' + ('a' * 20) + '.' + ('b' * 20) + '.' + ('c' * 20)
        $credential = 'synthetic-' + ('x' * 24)
        $cases = @(
            @{ Name = 'private-key PEM'; Pattern = $script:pemPattern; Text = $begin + 'PRIVATE KEY' + $end },
            @{ Name = 'compact access token'; Pattern = $script:jwtPattern; Text = $jwt },
            @{ Name = 'authorization credential'; Pattern = $script:authorizationPattern; Text = 'Authorization: DPoP ' + $credential },
            @{ Name = 'JSON credential'; Pattern = $script:jsonCredentialPattern; Text = '"pass' + 'word":"' + $credential + '"' },
            @{ Name = 'environment assignment'; Pattern = $script:environmentAssignmentPattern; Text = $privateKeyName + '=' + $credential },
            @{ Name = 'PowerShell assignment'; Pattern = $script:powershellAssignmentPattern; Text = '$database' + $passwordName + " = '$credential'" },
            @{ Name = 'access-token assignment'; Pattern = $script:environmentAssignmentPattern; Text = $accessTokenName + '=' + $credential }
        )

        foreach ($case in $cases) {
            $casePath = Join-Path $tempDirectory 'synthetic.txt'
            [System.IO.File]::WriteAllText($casePath, $case.Text)
            $result = Invoke-LiteralSecretScan -Path $casePath -SearchPatterns @($case.Pattern)
            if (-not $result.Found) {
                throw "Literal-secret scanner self-test did not detect $($case.Name)."
            }
        }

        $safePath = Join-Path $tempDirectory 'safe-placeholders.txt'
        [System.IO.File]::WriteAllLines($safePath, @(
            $passwordName + '=<password>',
            $accessTokenName + '=${ACCESS_TOKEN}',
            '"password":"example-password"',
            'Authorization: DPoP <access-token>'
        ))
        $safeResult = Invoke-LiteralSecretScan -Path $safePath -SearchPatterns $script:patterns
        if ($safeResult.Found) {
            throw 'Literal-secret scanner self-test rejected documented placeholders.'
        }

        $excludedDirectory = Join-Path $tempDirectory 'build'
        New-Item -ItemType Directory -Path $excludedDirectory | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $excludedDirectory 'generated.txt'), $begin + 'PRIVATE KEY' + $end)
        Remove-Item -LiteralPath (Join-Path $tempDirectory 'synthetic.txt'), $safePath -Force
        $excludedResult = Invoke-LiteralSecretScan -Path $tempDirectory -SearchPatterns $script:patterns -Globs $script:excludedGlobs
        if ($excludedResult.Found) {
            throw 'Literal-secret scanner self-test did not honor generated/build exclusions.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

if ($SelfTest) {
    Assert-SyntheticCoverage
    Write-Output 'Literal-secret scanner synthetic coverage passed.'
    return
}

$scan = Invoke-LiteralSecretScan -Path $repoRoot -SearchPatterns $patterns -Globs $excludedGlobs
if ($scan.Found) {
    $relativePaths = @($scan.Paths | ForEach-Object {
        [System.IO.Path]::GetRelativePath($repoRoot, [string]$_)
    } | Sort-Object -Unique)
    Write-Error ('Literal-secret scan found prohibited content in: ' + ($relativePaths -join ', '))
    throw 'Literal-secret scan found prohibited content; matched values were suppressed.'
}
Write-Output 'Literal-secret scan found no prohibited literals in authored code, documentation, configuration, or scripts.'
