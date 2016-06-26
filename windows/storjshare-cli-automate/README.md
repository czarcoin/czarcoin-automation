Storj Share CLI - Windows Automation
===============

PowerShell script to automate the Storj Share CLI installation and setup

Prerequisites
-------------

* Windows 7 or later
* Windows Server 2008 or later
* PowerShell Version 2 or later

### Background

This default configuration of the script automates the following functions:

```
--Installs all pre-requisites as listed: <a href="https://github.com/Storj/storjshare-cli#prerequisites">https://github.com/Storj/storjshare-cli#prerequisites<a/>
--Sets required Windows environment variables
--Builds storjshare-cli
--Enables UPNP on Windows
```

### Usage Instructions
```
1.) Download Latest Release of storj-automation (<a href="https://github.com/Storj/storj-automation/archive/master.zip">https://github.com/Storj/storj-automation/archive/master.zip</a>)
2.) Extract the ZIP, and navigate to `storj-automation-master\windows\storjshare-cli-automate`
3.) Double-click `install.bat`
4.) (if prompted) Click Yes on the User Account Control (UAC) screen
5.) Reboot when completed
6.) Double-click `install.bat`
7.) Installation should now be completed. Follow <a href="https://github.com/Storj/storjshare-cli#usage">https://github.com/Storj/storjshare-cli#usage</a> to complete.
```

### Advanced Functionality:

Extra commands that can be run to adjust the usage of the script

To deploy silently use the following command
`./automate_storj_cli.ps1 -silent`

To install storjshare-cli as a service use the following command
`./automate_storj_cli.ps1 -installsvc -svcname storjshare -datadir C:\storjshare -password 4321`

To remove service use the following command
`./automate_storj_cli.ps1 -removesvc -svcname storjshare`

To disable UPNP
`./automate_storj_cli.ps1 -noupnp`
