@echo off
rem Builds dist\ProxyLatch.exe (single file, asks for admin on launch)
rem The window stays open at the end unless the CI variable is set (GitHub Actions).
setlocal
cd /d "%~dp0"

echo === Installing / upgrading build tools ===
python -m pip install --upgrade -r requirements.txt pyinstaller pyinstaller-hooks-contrib altgraph
if errorlevel 1 goto :fail

for /f "delims=" %%i in ('python -c "import pydivert,os;print(os.path.join(os.path.dirname(pydivert.__file__),'windivert_dll'))"') do set "WD=%%i"
if not exist "%WD%\WinDivert64.sys" (
  echo WinDivert files not found in "%WD%"
  goto :fail
)

echo.
echo === Building ProxyLatch.exe ===
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name ProxyLatch ^
  --add-binary "%WD%\WinDivert64.dll;windivert" ^
  --add-binary "%WD%\WinDivert64.sys;windivert" ^
  proxylatch.py
if errorlevel 1 goto :fail

echo.
echo Done: %~dp0dist\ProxyLatch.exe
if not defined CI pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see the messages above.
if not defined CI pause
exit /b 1
