@echo off
py run_scan.py
if errorlevel 9009 python run_scan.py
pause
