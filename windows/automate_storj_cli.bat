@ECHO OFF
REM **************************************** 
REM Automation Menu
REM Runs Powershells easily
REM Be sure to run this as an administrator (Right-click Run As Administrator)
REM ****************************************

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0install_storj_cli.ps1.ps1'"

PAUSE
