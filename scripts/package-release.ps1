# Hizli dagitim: Release EXE + windeployqt ile tek klasor paket (StarLoader)
# Kullanim: powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1
# Cikti:  release-package/  (zip'leyip dagitabilirsin)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
$QtBin = "C:\Qt\6.11.1\mingw_64\bin"
$BuildDir = "$ProjectRoot\build"
$PackageDir = "$ProjectRoot\release-package"

Write-Host "=== StarLoader Release Paketleme ===" -ForegroundColor Cyan
Write-Host "Qt: $QtBin"
Write-Host "Build: $BuildDir"
Write-Host "Paket: $PackageDir"

# PATH'e MinGW ekle (Ninja/MinGW icin sart)
$env:PATH = "C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\CMake_64\bin;$env:PATH"

# 1. Release build (CMakePresets kullan)
Set-Location $ProjectRoot
# Preset varsa onu kullan, yoksa manuel configure
if (Test-Path "$ProjectRoot\build\build.ninja") {
    Write-Host "Mevcut build bulundu, sadece build calisiyor..." -ForegroundColor Yellow
    & "C:\Qt\Tools\CMake_64\bin\cmake.exe" --build $BuildDir --config Release 2>&1 | Write-Host
} else {
    Write-Host "Configure + build..." -ForegroundColor Yellow
    & "C:\Qt\Tools\CMake_64\bin\cmake.exe" --preset qt-mingw 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
    & "C:\Qt\Tools\CMake_64\bin\cmake.exe" --build $BuildDir --config Release 2>&1 | Write-Host
}
if ($LASTEXITCODE -ne 0) { throw "build failed" }

# 2. Paket klasorunu hazirla - build icinde zaten windeployqt calisti, dosyalari topla
if (Test-Path $PackageDir) { Remove-Item $PackageDir -Recurse -Force }
New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null

# LicenseClient ve HwidObtainer EXE'lerini bul
$licenseExe = Get-ChildItem $BuildDir -Recurse -Filter "LicenseClient.exe" | Select-Object -First 1
$hwidExe = Get-ChildItem $BuildDir -Recurse -Filter "HwidObtainer.exe" | Select-Object -First 1

if (-not $licenseExe) { throw "LicenseClient.exe bulunamadi: $BuildDir" }
Write-Host "LicenseClient: $($licenseExe.FullName)" -ForegroundColor Green

# Paket: LicenseClient klasoru
$licensePackage = Join-Path $PackageDir "LicenseClient"
New-Item -ItemType Directory -Path $licensePackage -Force | Out-Null
Copy-Item $licenseExe.FullName $licensePackage -Force
$licenseDir = Split-Path $licenseExe.FullName -Parent
# windeployqt zaten build'de calisti, ama paket icin tekrar calistir (temiz)
$windeployqt = Join-Path $QtBin "windeployqt.exe"
if (Test-Path $windeployqt) {
    Write-Host "windeployqt LicenseClient icin calisiyor..." -ForegroundColor Yellow
    & $windeployqt --no-translations --compiler-runtime --openssl-root "C:/Qt/Tools/mingw1310_64/opt" "$licensePackage\LicenseClient.exe" 2>&1 | Write-Host
    # OpenSSL DLL'ini de kopyala (license-client CMakeLists zaten yapiyor ama pakete de)
    $cryptoDll = Get-ChildItem $licenseDir -Filter "libcrypto*.dll" | Select-Object -First 1
    if ($cryptoDll) { Copy-Item $cryptoDll.FullName $licensePackage -Force }
}

if ($hwidExe) {
    Write-Host "HwidObtainer: $($hwidExe.FullName)" -ForegroundColor Green
    $hwidPackage = Join-Path $PackageDir "HwidObtainer"
    New-Item -ItemType Directory -Path $hwidPackage -Force | Out-Null
    Copy-Item $hwidExe.FullName $hwidPackage -Force
    if (Test-Path $windeployqt) {
        & $windeployqt --no-translations --compiler-runtime "$hwidPackage\HwidObtainer.exe" 2>&1 | Write-Host
    }
}

Write-Host "`n=== Paket icerigi ===" -ForegroundColor Cyan
Get-ChildItem $PackageDir -Recurse | Format-Table FullName, Length -AutoSize -Wrap | Out-String | Write-Host

Write-Host "`n=== DLL bagimlilik kontrol (LicenseClient) ===" -ForegroundColor Cyan
& "C:\Qt\Tools\mingw1310_64\bin\objdump.exe" -p "$licensePackage\LicenseClient.exe" | Select-String "DLL Name" | Out-String | Write-Host

Write-Host @"
`n✓ Paket hazir: $PackageDir
  Klasorleri zip'le ve dagit.

  NOT: Bu hala "tek klasor" dagitimdir. Gercek "tek EXE" icin:
    1) powershell -ExecutionPolicy Bypass -File C:\Qt\build-qt-static.ps1
       veya .\scripts\build-qt-static.ps1  (bir kez, 2-4 saat)
    2) Qt Creator'da "Qt6 Static MinGW" kitiyle Release al
       Kit CMake ayari: -DCMAKE_PREFIX_PATH=C:/Qt/6-static -DSTARLOADER_STATIC=ON
"@ -ForegroundColor Green
