@echo off
setlocal

:: ============================================================================
:: AffinityManager Service Installer & Compiler
:: ============================================================================
:: This script compiles the C++ source, then installs or uninstalls the service.
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
echo   1. Compile and Install Service
echo   2. Uninstall Service
echo   3. Exit
echo.
set /p "choice=Enter your choice (1, 2, or 3) and press Enter: "

if "%choice%"=="1" goto install_service
if "%choice%"=="2" goto uninstall_service
if "%choice%"=="3" goto :eof

echo.
echo Invalid choice. Please try again.
pause
goto menu


:install_service
    echo.
    echo --- Starting Installation ---

    :: 1. Compile the source code
    echo.
    echo [1/4] Compiling %SOURCEFILE%...
    g++ -o %EXECUTABLE% %SOURCEFILE% -municode -static -lstdc++ -lole32 -loleaut32 -lwbemuuid -lpowrprof
    if not exist "%EXECUTABLE%" (
        echo ERROR: Compilation failed. Please check for errors above.
        pause
        goto :eof
    )
    echo Compilation successful.

    :: 2. Handle existing service installation
    echo.
    echo [2/4] Checking for existing service...
    sc query %SERVICENAME% >nul 2>&1
    if %errorlevel% == 0 (
        echo Service is already installed. Stopping and removing it for re-installation...
        net stop %SERVICENAME% >nul 2>&1
        sc delete %SERVICENAME% >nul 2>&1
        timeout /t 2 /nobreak >nul
    )

    :: 3. Prepare target directory and files
    echo.
    echo [3/4] Preparing installation directory and files...
    if not exist "%TARGETDIR%" mkdir "%TARGETDIR%"
    copy /Y "%EXECUTABLE%" "%TARGETDIR%\" >nul
    if not exist "%TARGETDIR%\games.txt" ( if exist "games.txt" ( copy "games.txt" "%TARGETDIR%\games.txt" >nul ) else ( echo.>"%TARGETDIR%\games.txt" ) )
    if not exist "%TARGETDIR%\background.txt" ( if exist "background.txt" ( copy "background.txt" "%TARGETDIR%\background.txt" >nul ) else ( echo.>"%TARGETDIR%\background.txt" ) )

    :: 4. Create and start the new service
    echo.
    echo [4/4] Creating and starting the service...
    sc create %SERVICENAME% binPath=%BINARYPATH% start=auto DisplayName="%DISPLAYNAME%"
    if %errorlevel% neq 0 (
        echo ERROR: Service creation failed.
        pause
        goto :eof
    )
    
    sc description %SERVICENAME% "Manages process CPU affinities and performance state based on predefined lists."
    
    echo Starting service...
    net start %SERVICENAME%
    
    echo.
    echo --- Installation Complete ---
    pause
    goto :eof

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
    goto :eof
