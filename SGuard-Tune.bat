@echo off
chcp 65001 >nul
setlocal
set "PS1=%~dp0SGuard-Tune.ps1"
if not exist "%PS1%" (
  echo SGuard-Tune.ps1 not found next to this file.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -AutoLogin %*
echo.
echo --- done, window will stay open ---
pause
