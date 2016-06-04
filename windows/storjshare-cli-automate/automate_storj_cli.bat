@ECHO OFF
REM **************************************** 
REM Storj-cli Windows Automation Menu
REM ****************************************

SET install=%~dp0install_storj_cli.ps1

IF NOT EXIST "%install%" (
	ECHO File %install% Does Not Exist
	PAUSE
	EXIT
)

REM Run install_storj_cli.ps1 Power Shell Script
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%install%""' -Verb RunAs}"
