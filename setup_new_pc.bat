@echo off
echo =======================================================
echo    Mini SIEM - New PC Setup
echo =======================================================
echo.
echo Make sure you have installed:
echo 1. Python 3
echo 2. Docker Desktop (and it is running!)
echo 3. Ollama (if you want the AI to work locally)
echo.
pause

set PORTABLE_DIR=%~dp0
set APP_DIR=%PORTABLE_DIR%app
set DOCKER_DIR=%PORTABLE_DIR%docker
set OLLAMA_DIR=%PORTABLE_DIR%ollama

echo.
echo [1/5] Restoring Ollama Models...
if exist "%OLLAMA_DIR%\models" (
    xcopy /E /I /Y "%OLLAMA_DIR%\*" "%USERPROFILE%\.ollama\"
    echo Ollama models copied.
) else (
    echo No Ollama models found to restore.
)

echo.
echo [2/5] Loading Docker Images...
if exist "%DOCKER_DIR%\images\opensearch.tar" (
    docker load -i "%DOCKER_DIR%\images\opensearch.tar"
)
if exist "%DOCKER_DIR%\images\dashboards.tar" (
    docker load -i "%DOCKER_DIR%\images\dashboards.tar"
)

echo.
echo [3/5] Starting Docker Containers...
cd /d "%DOCKER_DIR%"
docker-compose up -d

echo.
echo [4/5] Restoring Docker Data Volume...
if exist "%DOCKER_DIR%\data_backup\opensearch-data-backup.tar.gz" (
    echo Stopping containers to restore data...
    docker-compose stop
    
    echo Restoring data...
    docker run --rm -v opensearch-lab_opensearch-data:/volume -v "%DOCKER_DIR%\data_backup:/backup" alpine sh -c "cd /volume && tar -xzf /backup/opensearch-data-backup.tar.gz"
    
    echo Restarting containers...
    docker-compose start
) else (
    echo No Docker volume backup found. Starting fresh.
)

echo.
echo [5/5] Setting up Python Environment...
cd /d "%APP_DIR%"
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat
echo Installing requirements...
pip install -r requirements.txt

echo.
echo =======================================================
echo Setup Complete!
echo You can now run the portal by executing:
echo cd app ^&^& venv\Scripts\activate ^&^& python app.py
echo =======================================================
pause
