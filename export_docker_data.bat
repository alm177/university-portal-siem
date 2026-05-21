@echo off
echo =======================================================
echo    Mini SIEM Docker Exporter
echo =======================================================
echo.
echo Please ensure Docker Desktop is RUNNING before continuing.
pause

set EXPORT_DIR=%~dp0docker\images
set DATA_DIR=%~dp0docker\data_backup

if not exist "%EXPORT_DIR%" mkdir "%EXPORT_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

echo.
echo [1/3] Exporting OpenSearch Image...
docker save -o "%EXPORT_DIR%\opensearch.tar" opensearchproject/opensearch:2.13.0
if %errorlevel% neq 0 (
    echo [ERROR] Failed to export OpenSearch. Is Docker running?
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Exporting OpenSearch Dashboards Image...
docker save -o "%EXPORT_DIR%\dashboards.tar" opensearchproject/opensearch-dashboards:2.13.0

echo.
echo [3/3] Backing up OpenSearch Data Volume...
echo This will start a temporary container to extract the volume data.
docker run --rm -v opensearch-lab_opensearch-data:/volume -v "%DATA_DIR%:/backup" alpine tar -czf /backup/opensearch-data-backup.tar.gz -C /volume .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to backup volume. Check if the volume name 'opensearch-lab_opensearch-data' is correct.
    pause
    exit /b %errorlevel%
)

echo.
echo =======================================================
echo Export Complete!
echo You can now move this portable folder to your new PC.
echo =======================================================
pause
