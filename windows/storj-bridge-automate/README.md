Storj Bridge - Windows Automation
===============

PowerShell script to automate the Storj Bridge installation and setup

Prerequisites
-------------

* Windows 7 or later
* Windows Server 2008 or later
* PowerShell Version 2 or later

### Background

This default configuration of the script automates the following functions:

```
--Installs all pre-requisites as listed: xxxx
--Sets required Windows environment variables
--Builds storj-bridge
--Disables UPNP on Windows
```

### Usage Instructions

```
1.) Download Latest Release of storj-automation - https://github.com/Storj/storj-automation/archive/master.zip
2.) Extract the ZIP, and navigate to `storj-automation-master\windows\storjshare-bridge-automate`
3.) Double-click `install.bat`
4.) (if prompted) Click Yes on the User Account Control (UAC) screen
5.) Reboot when completed
6.) Double-click `install.bat`
7.) Installation should now be completed. Follow xxx to complete.
```

### Advanced Functionality:

Extra commands that can be run to adjust the usage of the script

To deploy silently use the following command
`./automate_storj_bridge.ps1 -silent`

To prevent from storj-bridge from being installed as a service
`./automate_storj_bridge.ps1 -nosvc`

To remove service use the following command
`./automate_storj_bridge.ps1 -removesvc`

To enable UPNP
`./automate_storj_bridge.ps1 -enableupnp`

To run as a service account (*recommended for automated deployment situations*)
`./automate_storj_bridge.ps1 -runas -username username -password 'password'`

### Output Results
In silent mode, the output error numbers coincide with Microsoft's MSI standards
Return Codes (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
