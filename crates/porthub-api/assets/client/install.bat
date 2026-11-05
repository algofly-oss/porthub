@echo off
setlocal
powershell.exe -NoProfile -EncodedCommand {{PAYLOAD}}
exit /b %errorlevel%
