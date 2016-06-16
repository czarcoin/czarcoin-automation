@ECHO OFF
REM ****************************************
REM Storj-cli Drive Usage Report
REM ****************************************

SET install=%~dp0storjshare-drive-usage.ps1

IF NOT EXIST "%install%" (
	ECHO File %install% Does Not Exist
	PAUSE
	EXIT
)

REM Run Power Shell Script
PowerShell.exe -NoProfile -Command "& {Unblock-File '%install%'}"
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass & {&''%install%''}' -Verb RunAs}"
