Storj - Windows Automation
===============

PowerShell script to automate the Storj Share CLI installation and setup

Prerequisites
-------------

* Windows 7 or later
* Windows Server 2008 or later
* PowerShell Version 3 or later

### Background

This default configuration of the script automates the following functions:

```
--Installs all pre-requisites as listed: https://github.com/Storj/storjshare-cli#prerequisites
--Sets required Windows environment variables
--Builds storj
```

### Usage Instructions

```
1.) Download Latest Release of storj-automation - https://github.com/Storj/storj-automation/archive/master.zip
2.) Extract the ZIP, and navigate to `storj-automation-master\windows\storjshare-cli-automate`
3.) Double-click `install.bat`
4.) (if prompted) Click Yes on the User Account Control (UAC) screen
5.) Reboot when completed
6.) Double-click `install.bat`
7.) Installation should now be completed. Follow https://github.com/Storj/storjshare-cli#usage to complete.
```
### Logging

Log files are stored in `%TEMP%\storj\core`

  ### Output Results
In silent mode, the output error numbers coincide with Microsoft's MSI standards
Return Codes (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
