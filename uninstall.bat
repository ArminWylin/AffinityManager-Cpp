@echo off
setlocal

:: ============================================================================
:: AffinityManager Service Uninstaller
:: ============================================================================
:: This script stops and removes the AffinityManager service and cleans up
:: all associated files. It must be run with administrative privileges.
:: ============================================================================

set "SERVICENAME=AffinityManager"
set "TARGETDIR=%ProgramData%\AffinityManager"

:check_permissions
    echo Checking for administrative privileges...
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo Administrative permissions confirmed.
    ) else (
        echo.
        echo ERROR: This script requires administrative privileges.
        echo Please right-click on uninstall.bat and select "Run as administrator".
        echo.
        pause
        exit /b 1
    )

echo.
echo Uninstalling %SERVICENAME%...
echo.

echo Stopping service...
net stop %SERVICENAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo Service was not running or could not be stopped.
) else (
    echo Service stopped successfully.
)

echo.
echo Deleting service...
sc delete %SERVICENAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo Service was not found or could not be deleted.
) else (
    echo Service deleted successfully.
)

echo.
echo Cleaning up installation directory: %TARGETDIR%
if exist "%TARGETDIR%" (
    rem Add a short delay to ensure the service executable file is unlocked
    echo Waiting for files to be released...
    timeout /t 3 /nobreak >nul
    
    rmdir /s /q "%TARGETDIR%"
    if %errorlevel% neq 0 (
        echo Failed to remove the directory. It may be in use.
    ) else (
        echo Directory removed successfully.
    )
) else (
    echo Installation directory not found.
)

echo.
echo Uninstallation complete.
pause
