@echo off
setlocal enabledelayedexpansion
title PenHub — Offline Installer

set DIR=%~dp0
set PACKAGES_DIR=%DIR%packages
set PYTHON_INSTALLER=%DIR%python-3.12.10-amd64.exe
set PYTHON_EXE=

echo ================================================================
echo   PenHub — Offline Python + Dependencies Installer
echo   Python 3.12/3.14  ^|  FastAPI / Uvicorn / OpenPyXL / Multipart
echo ================================================================
echo.

rem ── Check/Install Python ─────────────────────────────────────────

:find_python
set PYTHON_EXE=

rem Try common names in PATH
for %%P in (python py python3) do (
    where %%P >nul 2>&1
    if !errorlevel!==0 (
        set PYTHON_EXE=%%P
        goto :check_python_version
    )
)

rem Try default Python 3.14 install paths
if exist "C:\Python314\python.exe" (
    set PYTHON_EXE=C:\Python314\python.exe
    goto :check_python_version
)
if exist "%LocalAppData%\Programs\Python\Python314\python.exe" (
    set PYTHON_EXE=%LocalAppData%\Programs\Python\Python314\python.exe
    goto :check_python_version
)

rem Try default Python 3.12 install paths
if exist "C:\Python312\python.exe" (
    set PYTHON_EXE=C:\Python312\python.exe
    goto :check_python_version
)
if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set PYTHON_EXE=%LocalAppData%\Programs\Python\Python312\python.exe
    goto :check_python_version
)

:no_python
echo [PYTHON] Python not found in PATH.
if not exist "%PYTHON_INSTALLER%" (
    echo ERROR: Python installer not found: %PYTHON_INSTALLER%
    echo.
    echo Please download python-3.12.10-amd64.exe from:
    echo   https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe
    echo and place it next to this install.bat
    echo.
    pause
    exit /b 1
)
echo [PYTHON] Installing Python 3.12.10 (user install, no admin needed)...
"%PYTHON_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1
if !errorlevel! neq 0 (
    echo [PYTHON] User install failed, trying system install (may need admin)...
    "%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    if !errorlevel! neq 0 (
        echo ERROR: Python installation failed. Try running as Administrator.
        pause
        exit /b 1
    )
)
echo [PYTHON] Python 3.12.10 installed.
echo.

rem Refresh PATH after install
set "PATH=%LocalAppData%\Programs\Python\Python314;%LocalAppData%\Programs\Python\Python314\Scripts;%PATH%"
set "PATH=%LocalAppData%\Programs\Python\Python312;%LocalAppData%\Programs\Python\Python312\Scripts;%PATH%"
set "PATH=C:\Python314;C:\Python314\Scripts;%PATH%"
set "PATH=C:\Python312;C:\Python312\Scripts;%PATH%"
goto :find_python

:check_python_version
echo [PYTHON] Found: %PYTHON_EXE%
%PYTHON_EXE% --version
echo.

rem ── Install packages ─────────────────────────────────────────────

if not exist "%PACKAGES_DIR%" (
    echo ERROR: packages\ folder not found next to install.bat
    pause
    exit /b 1
)

echo [PIP] Installing packages from local folder (no internet)...
echo       Source: %PACKAGES_DIR%
echo.

%PYTHON_EXE% -m pip install ^
    fastapi uvicorn openpyxl python-multipart ^
    --no-index ^
    --find-links "%PACKAGES_DIR%" ^
    --no-warn-script-location ^
    -q

if !errorlevel!==0 (
    echo [PIP] All packages installed via pip.
    goto :verify
)

echo.
echo [PIP] pip install failed. Trying fallback manual extraction...
%PYTHON_EXE% "%DIR%install_fallback.py"
if !errorlevel! neq 0 (
    echo ERROR: Installation failed. Check Python version and try as Administrator.
    pause
    exit /b 1
)

:verify
echo.
echo ── Verification ────────────────────────────────────────────────
%PYTHON_EXE% -c "import fastapi; print('  fastapi       ', fastapi.__version__)"
%PYTHON_EXE% -c "import uvicorn; print('  uvicorn       ', uvicorn.__version__)"
%PYTHON_EXE% -c "import openpyxl; print('  openpyxl      ', openpyxl.__version__)"
%PYTHON_EXE% -c "import multipart; print('  multipart     ', multipart.__version__)"
%PYTHON_EXE% -c "import pydantic; print('  pydantic      ', pydantic.__version__)"

echo.
echo ================================================================
echo   All done! PenHub dependencies are ready.
echo   Start server:  python server.py --host 0.0.0.0 --port 322 --password "YourPass"
echo ================================================================
echo.
pause
