@ECHO OFF
REM ****************************************
REM Storj-cli Windows Automation Menu
REM ****************************************

SET install=%~dp0automate_storj_cli.ps1

IF NOT EXIST "%install%" (
	ECHO File %install% Does Not Exist
	PAUSE
	EXIT
)

REM Run automate_storj_cli.ps1 Power Shell Script
PowerShell.exe -NoProfile -Command "& {Unblock-File '%install%'}"
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass & {&''%install%''}' -Verb RunAs}"
