@echo off
REM Compila o DiagTool.exe (execute no Windows 10/11 com Python 3.9+ instalado)
cd /d "%~dp0"
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pytest -q
if errorlevel 1 (echo Testes falharam. & exit /b 1)
python build.py
echo.
echo Pronto: dist\DiagTool.exe
pause
