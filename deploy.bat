@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if "%~1"=="" goto usage

where ssh >nul 2>&1
if errorlevel 1 (
  echo OpenSSH Client is required. Install it from Windows Optional Features.
  exit /b 1
)
where tar >nul 2>&1
if errorlevel 1 (
  echo tar is required. It ships with Windows 10 and later.
  exit /b 1
)

set "TARGET=%~1"
set "REMOTE_DIR=/opt/privatevpn"
set "ARCHIVE=%TEMP%\privatevpn-deploy.tar"

echo Uploading this folder to %TARGET%:%REMOTE_DIR%
tar --exclude=.git --exclude=bin --exclude=*.exe --exclude=config.json --exclude=admin.password --exclude=data --exclude=*.db --exclude=*.tmp -cf "%ARCHIVE%" -C "%CD%" .
if errorlevel 1 exit /b 1

ssh -o StrictHostKeyChecking=accept-new %TARGET% "mkdir -p %REMOTE_DIR% && tar -xf - -C %REMOTE_DIR%" < "%ARCHIVE%"
set "SSH_ERR=%ERRORLEVEL%"
del /f /q "%ARCHIVE%" >nul 2>&1
if not "%SSH_ERR%"=="0" exit /b %SSH_ERR%

echo Running update on the server. First run installs. Later runs keep the password and keys.
ssh -o StrictHostKeyChecking=accept-new %TARGET% "sed -i 's/\r$//' %REMOTE_DIR%/deploy/*.sh && bash %REMOTE_DIR%/deploy/update.sh %~2 %~3 %~4 %~5 %~6 %~7 %~8 %~9"
set "SSH_ERR=%ERRORLEVEL%"
exit /b %SSH_ERR%

:usage
echo usage: deploy.bat user@HOST [--address IP] [--domain NAME]
echo.
echo Run from Command Prompt or PowerShell in this folder. SSH as root.
echo.
echo First time:
echo   deploy.bat root@203.0.113.10 --address 203.0.113.10 --domain vpn.example.com
echo.
echo Later updates keep the password, Reality keys, and device locks:
echo   deploy.bat root@203.0.113.10
exit /b 2