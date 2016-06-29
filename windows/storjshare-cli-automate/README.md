Storj Share CLI - Windows Automation
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
--Builds storjshare-cli
--Enables UPNP on Windows
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

Log files are stored in `%TEMP%\storj\cli`

### Inputs
  -silent - [optional] this will write everything to a log file and prevent the script from running pause commands.  
  -noupnp - [optional] Disables UPNP  
  -installsvc - [optional] Installs storjshare as a service (see the config section in the script to customize)  
    -svcname [name] - [optional] Installs the service with this name - storjshare-cli is default  
    -datadir [directory] - [required] Data Directory of Storjshare  
    -password [password] - [required] Password for Storjshare Directory  
  -removesvc - [optional] Removes storjshare as a service (see the config section in the script to customize)  
    -svcname [name] - required] Removes the service with this name (*becareful*)  
  -runas - [optional] Runs the script as a service account  
    -username username [required] Username of the account  
    -password 'password' [required] Password of the account  
  -autoreboot [optional] Automatically reboots if required  

### Advanced Functionality:

Extra commands that can be run to adjust the usage of the script

  To deploy silently use the following command
  ./automate_storj_cli.ps1 -silent

  To install service use the following command
  ./automate_storj_cli.ps1 -installsvc -datadir C:\storjshare -storjpassword 4321

  To remove service use the following command
  ./automate_storj_cli.ps1 -removesvc

  To disable UPNP
  ./automate_storj_cli.ps1 -noupnp

    To run as a service account in silent mode, no upnp, auto reboot, and install a service
  ./automate_storj_cli.ps1 -silent -runas -username username -storjpassword password -noupnp -autoreboot -installsvc -datadir C:\storjshare -password 4321
  
  ### Output Results
In silent mode, the output error numbers coincide with Microsoft's MSI standards
Return Codes (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
