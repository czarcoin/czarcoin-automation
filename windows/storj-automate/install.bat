@ECHO OFF
REM ****************************************
REM Storj Windows Automation Menu
REM ****************************************

SET install=%~dp0automate_storj.ps1

IF NOT EXIST "%install%" (
	ECHO File %install% Does Not Exist
	PAUSE
	EXIT
)

REM Run Power Shell Script
PowerShell.exe -NoProfile -Command "& {Unblock-File '%install%'}"
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -NonInteractive -NoLogo -NoExit -WindowStyle Normal -ExecutionPolicy Bypass & {&''%install%''}' -Verb RunAs}"
