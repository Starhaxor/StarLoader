#Requires -Version 5.1
<#
.SYNOPSIS
  Qt 6.11.1'i MinGW ile STATIK derleyip C:\Qt\6-static altina kurar.
  Sonuc: tek EXE (Qt6*.dll'siz) uretebilen static Qt kiti.

.NOTES
  - Kaynak yoksa otomatik indirir (Src yoksa)
  - 2-4 saat surer, ~15GB disk ister
  - Sadece bir kez calistirilir, sonra tum projeler ayni kiti kullanir
  - Qt Creator'da Kit olarak eklemen gerekir (script sonunda anlatiyor)

  Calistirma:
    powershell -ExecutionPolicy Bypass -File scripts\build-qt-static.ps1
  veya
    powershell -ExecutionPolicy Bypass -File scripts\build-qt-static.ps1 -SkipDownload
#>
param(
    [switch]$SkipDownload,
    [string]$QtVersion = "6.11.1",
    [string]$SrcDir = "C:\Qt\6.11.1\Src",
    [string]$BuildDir = "C:\Qt\build-qt-static",
    [string]$InstallDir = "C:\Qt\6-static"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# 1. On kontroller
Write-Step "On kontroller"
$mingwBin = "C:\Qt\Tools\mingw1310_64\bin"
$cmakeBin = "C:\Qt\Tools\CMake_64\bin"
$ninjaBin = "C:\Qt\Tools\Ninja"

if (-not (Test-Path "$mingwBin\g++.exe")) {
    throw "MinGW bulunamadi: $mingwBin\g++.exe yok. Qt Online Installer'dan MinGW 13.1 kur."
}
if (-not (Test-Path "$cmakeBin\cmake.exe")) {
    throw "CMake bulunamadi: $cmakeBin\cmake.exe"
}
# Ninja var mi?
$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if (-not $ninja) {
    if (Test-Path "$ninjaBin\ninja.exe") { $env:PATH = "$ninjaBin;$env:PATH" }
}

Write-Host "MinGW: $mingwBin"
& "$mingwBin\g++.exe" --version | Select-Object -First 1 | Write-Host
& "$cmakeBin\cmake.exe" --version | Select-Object -First 1 | Write-Host

# 2. Kaynak kontrol / indirme
Write-Step "Qt kaynagi kontrol ($SrcDir)"
if (-not (Test-Path "$SrcDir\configure.bat") -and -not (Test-Path "$SrcDir\qtbase\configure.bat")) {
    if ($SkipDownload) { throw "Kaynak yok ve -SkipDownload verildi: $SrcDir" }

    Write-Host "Src yok, indiriliyor..." -ForegroundColor Yellow
    # Qt MaintenanceTool veya online installer kaynak paketi yoksa
    # aqtinstall ile indir (pip gerekir)
    $zipUrl = "https://download.qt.io/official_releases/qt/6.11/$QtVersion/single/qt-everywhere-src-$QtVersion.zip"
    # mirror fallback
    $zipPath = "$env:TEMP\qt-everywhere-src-$QtVersion.zip"

    # Oncelik: C:\Qt\6.11.1\Src zaten yoksa, qt-everywhere'i indir
    Write-Host "Indiriliyor: $zipUrl"
    Write-Host "Hedef: $zipPath (yaklasik 1.2GB, uzun surebilir)..."

    # PowerShell 5.1 ile TLS 1.2 zorunlu
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Host "Indirme basarisiz, alternatif: pip install aqtinstall ile deneyin" -ForegroundColor Red
        Write-Host "  pip install aqtinstall"
        Write-Host "  aqt install-qt windows desktop $QtVersion win64_mingw --outputdir C:\Qt --archives qtbase qttools qtsvg qtbase --modules all"
        throw $_
    }

    Write-Host "Aciliyor..."
    Expand-Archive -LiteralPath $zipPath -DestinationPath "C:\Qt" -Force
    $extracted = "C:\Qt\qt-everywhere-src-$QtVersion"
    if (Test-Path $extracted) {
        if (Test-Path $SrcDir) { Remove-Item $SrcDir -Recurse -Force }
        Move-Item $extracted $SrcDir
    }
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-Host "Kaynak hazir: $SrcDir" -ForegroundColor Green
} else {
    Write-Host "Kaynak mevcut, indirme atlandi." -ForegroundColor Green
}

# configure.bat yolunu bul
$configure = if (Test-Path "$SrcDir\configure.bat") { "$SrcDir\configure.bat" } else { "$SrcDir\qtbase\configure.bat" }
Write-Host "configure: $configure"

# 3. Build klasoru hazirla
Write-Step "Build klasoru hazirlaniyor ($BuildDir)"
if (Test-Path $BuildDir) {
    Write-Host "Mevcut build klasoru temizleniyor..."
    Remove-Item $BuildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
Set-Location $BuildDir

# PATH'e MinGW ve CMake ekle (configure icin gerekli)
$env:PATH = "$mingwBin;$cmakeBin;$env:PATH"

# 4. Configure — STATIK Release (minimal, sadece Widgets/Network icin)
Write-Step "Configure (static, release, prefix=$InstallDir) - birkac dakika surer"
$configureArgs = @(
    "-static"
    "-release"
    "-prefix", $InstallDir
    "-opensource", "-confirm-license"
    "-nomake", "examples"
    "-nomake", "tests"
    "-skip", "qtwebengine"
    "-skip", "qtcanvaspainter"
    "-skip", "qtquick3d"
    "-skip", "qtquick3dphysics"
    "-skip", "qt3d"
    "-skip", "qtmultimedia"
    "-skip", "qtwayland"
    "-skip", "qtdatavis3d"
    "-skip", "qtcharts"
    "-skip", "qtgraphs"
    "-skip", "qtlottie"
    "-skip", "qtvirtualkeyboard"
    "-skip", "qtwebview"
    "-skip", "qtdoc"
    "-skip", "qtspeech"
    "-skip", "qtgrpc"
    "-skip", "qtopcua"
    "-skip", "qtmqtt"
    "-skip", "qtnetworkauth"
    "-opengl", "desktop"
    "-qt-zlib"
    "-qt-pcre"
    "-qt-libpng"
    "-qt-libjpeg"
    "-qt-freetype"
    "-schannel"
    "-qt-host-path", "C:/Qt/6.11.1/mingw_64"
)

Write-Host "Komut: $configure $($configureArgs -join ' ')"
& $configure @configureArgs
if ($LASTEXITCODE -ne 0) { throw "configure basarisiz - kod $LASTEXITCODE" }

# 5. Build
Write-Step "Derleniyor (cmake --build . --parallel) — 2-4 SAAT surebilir!"
& "$cmakeBin\cmake.exe" --build . --parallel
if ($LASTEXITCODE -ne 0) { throw "build basarisiz - kod $LASTEXITCODE" }

# 6. Install
Write-Step "Install ($InstallDir)"
& "$cmakeBin\cmake.exe" --install .
if ($LASTEXITCODE -ne 0) { throw "install basarisiz - kod $LASTEXITCODE" }

Write-Host "`n✓ Static Qt kuruldu: $InstallDir" -ForegroundColor Green
Write-Host @"

── SONRAKI ADIMLAR (Qt Creator) ─────────────────────────────────────
1. Qt Creator > Ayarlar > Qt Versions > Ekle
   qmake: C:\Qt\6-static\bin\qmake.exe  (veya C:\Qt\6-static\bin\qmake6.exe)

2. Kits > Ekle:
   Name:     Qt6 Static MinGW
   Qt version: C:\Qt\6-static   (az once ekledigin)
   Compiler: MinGW 13.1 64-bit (C:\Qt\Tools\mingw1310_64\bin\g++.exe)
   CMake:    C:\Qt\Tools\CMake_64\bin\cmake.exe
   CMake Configuration ekle:
     -DCMAKE_PREFIX_PATH:PATH=C:/Qt/6-static

3. StarInjector'u ac, Kit olarak "Qt6 Static MinGW" sec, Release build al.
   Artik tek EXE: StarInjector.exe (Qt6*.dll'siz, libgcc/libstdc++ de icinde)

4. Dogrulama:
   objdump -p StarInjector.exe | grep "DLL Name"
   Sadece KERNEL32.dll, USER32.dll gibi sistem DLL'leri kalmali;
   Qt6Core.dll / libgcc_s_seh-1.dll gorunmemeli.

── NOT ──────────────────────────────────────────────────────────────
- Ekstra DLL kullanan projeler (OpenSSL dis DLL, FFmpeg, libcurl DLL)
  static Qt olsa bile o DLL yine gerekir. Onlari da -static baglamak
  veya yanina koymak gerekir.
- Gelistirirken normal "Qt 6.11.1 MinGW" kiti, dagitirken "Static" kiti kullan.
"@ -ForegroundColor Yellow

