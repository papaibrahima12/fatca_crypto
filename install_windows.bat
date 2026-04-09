@echo off
:: =============================================================================
:: FATCA Crypto Utility — Windows Installer
::
:: This script installs FATCACrypto.exe on the user's machine:
::   1. Copies the executable to %LOCALAPPDATA%\FATCACrypto\
::   2. Creates a desktop shortcut
::   3. Creates a Start Menu shortcut
::
:: Usage: Double-click this file or run: install_windows.bat
:: =============================================================================

setlocal

set "APP_NAME=FATCA Crypto"
set "EXE_NAME=FATCACrypto.exe"
set "INSTALL_DIR=%LOCALAPPDATA%\FATCACrypto"
set "DESKTOP=%USERPROFILE%\Desktop"
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs"

echo ================================================
echo   FATCA Crypto Utility — Installation
echo ================================================
echo.

:: Check if executable exists
if not exist "%~dp0dist\%EXE_NAME%" (
    echo [ERREUR] Executable introuvable: dist\%EXE_NAME%
    echo Veuillez d'abord builder l'application avec:
    echo   bash build_executable.sh --gui
    pause
    exit /b 1
)

:: Create install directory
echo [1/3] Creation du dossier d'installation...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy executable
echo [2/3] Copie de l'application...
copy /Y "%~dp0dist\%EXE_NAME%" "%INSTALL_DIR%\%EXE_NAME%" >nul
if errorlevel 1 (
    echo [ERREUR] Impossible de copier l'executable.
    pause
    exit /b 1
)

:: Create desktop shortcut via PowerShell
echo [3/3] Creation du raccourci sur le Bureau...
powershell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell; ^
     $s = $ws.CreateShortcut('%DESKTOP%\%APP_NAME%.lnk'); ^
     $s.TargetPath = '%INSTALL_DIR%\%EXE_NAME%'; ^
     $s.WorkingDirectory = '%INSTALL_DIR%'; ^
     $s.Description = 'FATCA Crypto Utility - Encryption/Decryption IRS IDES'; ^
     $s.Save()"

:: Create Start Menu shortcut
powershell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell; ^
     $s = $ws.CreateShortcut('%START_MENU%\%APP_NAME%.lnk'); ^
     $s.TargetPath = '%INSTALL_DIR%\%EXE_NAME%'; ^
     $s.WorkingDirectory = '%INSTALL_DIR%'; ^
     $s.Description = 'FATCA Crypto Utility - Encryption/Decryption IRS IDES'; ^
     $s.Save()"

echo.
echo ================================================
echo   Installation terminee avec succes!
echo ================================================
echo.
echo   Application installee dans: %INSTALL_DIR%
echo   Raccourci cree sur le Bureau: %DESKTOP%\%APP_NAME%.lnk
echo.
echo   Double-cliquez sur l'icone "%APP_NAME%" sur votre Bureau
echo   pour lancer l'application.
echo.
pause
