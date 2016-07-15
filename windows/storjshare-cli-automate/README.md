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
    -storjpassword [password] - [required] Password for Storjshare Directory
  -removesvc - [optional] Removes storjshare as a service (see the config section in the script to customize)
    -svcname [name] - required] Removes the service with this name (*becareful*)
  -runas - [optional] Runs the script as a service account
    -username username [required] Username of the account
    -password 'password' [required] Password of the account
  -autoreboot [optional] Automatically reboots if required
  -autosetup
    -datadir [directory] - [optional] Data Directory of Storjshare
    -storjpassword [password] - [required] Password for Storjshare Directory
    -publicaddr [ip or dns] - [optional] Public IP or DNS of storjshare (Default: 127.0.0.1)
        *Note use [THIS] to use the the hostname of the computer
        For example: [THIS] replaces with hostname
        For example: [THIS].domain.com replaces with hostname.domain.com
    -svcport [port number] - [optional] TCP Port Number of storjshare Service (Default: 4000)
    -nat [true | false] - [optional] Turn on or Off Nat (UPNP) [Default: true]
    -uri [uri of known good seed] - [optional] URI of a known good seed (Default: [blank])
    -loglvl [integer 1-4] - [optional] Logging Level of storjshare (Default: 3)
    -amt [number with unit] - [optional] Amount of space allowed to consume (Default: 2GB)
    -concurrency [integer] - [optional] Modifying this value can cause issues with getting contracts!
                             [warn]   See: http://docs.storj.io/docs/storjshare-troubleshooting-guide#rpc-call-timed-out
    -payaddr [storj addr] - [optional] Payment address STORJ wallet (Default: [blank; free])
    -tunconns [integer] - [optional] Number of allowed tunnel connections (Default: 3)
    -tunsvcport [port number] - [optional] Port number of Tunnel Service (Default: 0; random)
    -tunstart [port number] - [optional] Starting port number (Default: 0; random)
    -tunend [port number] - [optional] Ending port number (Default: 0; random)
   -noautoupdate
        -howoften - [optional] Days to check for updates (Default: Every day)
        -checktime - [optional] Time to check for updates (Default: 3:00am Local Time)
   -update - [optional] Performs an update only function and skips the rest

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
