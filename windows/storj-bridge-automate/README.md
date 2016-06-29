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

*Installs all pre-requisites as listed: <a href="https://github.com/Storj/bridge/">https://github.com/Storj/bridge/</a>  
*Sets required Windows environment variables  
*Builds storj-bridge  
*Disables UPNP on Windows  

### Usage Instructions

1. Download Latest Release of storj-automation - <a href="https://github.com/Storj/storj-automation/archive/master.zip">https://github.com/Storj/storj-automation/archive/master.zip</a>
2. Extract the ZIP, and navigate to `storj-automation-master\windows\storjshare-bridge-automate`
3. Double-click `install.bat`
4. (if prompted) Click Yes on the User Account Control (UAC) screen
5. Reboot when completed
6. Double-click `install.bat`
7. Installation should now be completed.
8. Navigate to `%USERPROFILE%\.storjshare\config\` and edit `production` in a text editor
9. Open services.msc and look for storj-bridge and start the service and ensure it starts without error.
10. It should now be working and processing.  
** You can verify it is working by going to reviewing the logs located at: `%TEMP%\storj\bridge\storj-bridge.log`  
** Also you can verify it is working by going to http://127.0.0.1 from the bridge server itself to see if it loads the webpage  

### Logging

Log files are stored in `%TEMP%\storj\bridge`

`storj-bridge.log` will contain the storj bridge service details and you can confirm if it is working properly there.

### Advanced Functionality

Extra commands that can be run to adjust the usage of the script

To deploy silently use the following command
`./automate_storj_bridge.ps1 -silent`

To deploy silently and suppress auto-reboot
`./automate_storj_bridge.ps1 -silent -noreboot`

To prevent from storj-bridge from being installed as a service
`./automate_storj_bridge.ps1 -nosvc`

To remove service use the following command
`./automate_storj_bridge.ps1 -removesvc`

To enable UPNP
`./automate_storj_bridge.ps1 -enableupnp`

To run as a service account (*recommended for automated deployment situations* / Besure to deploy as a user and not as NT\Authority System otherwise it will fail)

`./automate_storj_bridge.ps1 -runas -username username -password 'password'`

### Output Results
In silent mode, the output error numbers coincide with Microsoft's MSI standards
Return Codes (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
