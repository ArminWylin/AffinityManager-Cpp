@echo off
setlocal

:: ============================================================================
:: AffinityManager Service Installer & Compiler
:: ============================================================================
:: This script provides options to compile the C++ source, install or uninstall the service.
:: It must be run with administrative privileges.
:: ============================================================================

:: Change directory to the script's location to ensure files are found
cd /d "%~dp0"

set "SERVICENAME=AffinityManager"
set "DISPLAYNAME=CPU Affinity Manager"
set "TARGETDIR=%ProgramData%\AffinityManager"
set "SOURCEFILE=main.cpp"
set "EXECUTABLE=affinitymanager.exe"
set "BINARYPATH="%TARGETDIR%\%EXECUTABLE%""

:check_permissions
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo Administrative permissions confirmed.
    ) else (
        echo ERROR: This script requires administrative privileges.
        echo Please right-click and select "Run as administrator".
        pause
        exit /b 1
    )

:: --- Interactive Menu ---
:menu
cls
echo.
echo   AffinityManager Service Installer
echo   =================================
echo.
echo   1. Compile the program
echo   2. Install the service
echo   3. Uninstall the service
echo   4. Exit
echo.
set /p "choice=Enter your choice (1, 2, 3, or 4) and press Enter: "

if "%choice%"=="1" goto compile
if "%choice%"=="2" goto install_service
if "%choice%"=="3" goto uninstall_service
if "%choice%"=="4" goto :eof

echo.
echo Invalid choice. Please try again.
pause
goto menu

:compile
echo.
echo --- Compiling %SOURCEFILE% ---
g++ -o %EXECUTABLE% %SOURCEFILE% -municode -static -lstdc++ -lole32 -loleaut32 -lwbemuuid -lpowrprof
if not exist "%EXECUTABLE%" (
    echo ERROR: Compilation failed. Please check for errors above.
) else (
    echo Compilation successful.
)
pause
goto menu

:install_service
echo.
echo --- Starting Installation ---

:: Check if executable exists
if not exist "%EXECUTABLE%" (
    echo ERROR: The executable %EXECUTABLE% does not exist. Please compile the program first.
    pause
    goto menu
)

:: 1. Handle existing service installation
echo.
echo [1/3] Checking for existing service...
sc query %SERVICENAME% >nul 2>&1
if %errorLevel% == 0 (
    echo Service is already installed. Stopping and removing it for re-installation...
    net stop %SERVICENAME% >nul 2>&1
    sc delete %SERVICENAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: 2. Prepare target directory and files
echo.
echo [2/3] Preparing installation directory and files...
if not exist "%TARGETDIR%" mkdir "%TARGETDIR%"
copy /Y "%EXECUTABLE%" "%TARGETDIR%\" >nul
if not exist "%TARGETDIR%\games.txt" ( if exist "games.txt" ( copy "games.txt" "%TARGETDIR%\games.txt" >nul ) else ( echo.>"%TARGETDIR%\games.txt" ) )
if not exist "%TARGETDIR%\background.txt" ( if exist "background.txt" ( copy "background.txt" "%TARGETDIR%\background.txt" >nul ) else ( echo.>"%TARGETDIR%\background.txt" ) )
if not exist "%TARGETDIR%\all_cores_idle.txt" ( if exist "all_cores_idle.txt" ( copy "all_cores_idle.txt" "%TARGETDIR%\all_cores_idle.txt" >nul ) else ( echo.>"%TARGETDIR%\all_cores_idle.txt" ) )

:: 3. Create and start the new service
echo.
echo [3/3] Creating and starting the service...
sc create %SERVICENAME% binPath=%BINARYPATH% start=auto DisplayName="%DISPLAYNAME%"
if %errorlevel% neq 0 (
    echo ERROR: Service creation failed.
    pause
    goto menu
)

sc description %SERVICENAME% "Manages process CPU affinities and performance state based on predefined lists."

echo Starting service...
net start %SERVICENAME%

echo.
echo --- Installation Complete ---
pause
goto menu

:uninstall_service
echo.
echo Uninstalling %SERVICENAME%...

echo Stopping and deleting service...
net stop %SERVICENAME% >nul 2>&1
sc delete %SERVICENAME% >nul 2>&1

echo Cleaning up directory...
if exist "%TARGETDIR%" (
    timeout /t 2 /nobreak >nul
    rmdir /s /q "%TARGETDIR%"
)

echo.
echo Uninstallation complete.
pause
goto menu
