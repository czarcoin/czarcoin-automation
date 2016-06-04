@ECHO OFF
REM **************************************** 
REM Storj-cli Windows Automation Menu
REM ****************************************

REM Run install_storj_cli.ps1 Power Shell Script
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0install_storj_cli.ps1""' -Verb RunAs}"
