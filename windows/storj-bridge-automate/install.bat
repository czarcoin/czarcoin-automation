@ECHO OFF
REM ****************************************
REM Storj-bridge Windows Automation Menu
REM ****************************************

SET install=%~dp0automate_storj_bridge.ps1

IF NOT EXIST "%install%" (
	ECHO File %install% Does Not Exist
	PAUSE
	EXIT
)

REM Run automate_storj_bridge.ps1 Power Shell Script
PowerShell.exe -NoProfile -Command "& {Unblock-File '%install%'}"
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -NoLogo -NonInteractive -NoExit -ExecutionPolicy Bypass & {&''%install%''}' -Verb RunAs}"
