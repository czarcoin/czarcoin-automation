Provides a report of total disk space used based on the Drive/Folder specified
<br/>
<br/>INSTRUCTIONS:
<br/>1.) Download ZIP of storjshare-cli-automate (`https://github.com/Storj/storj-automation/archive/master.zip`)
<br/>2.) Extract ZIP and navigate to `storj-automation-master\windows\storjshare-drive-usage`
<br/>3.) Right-click `storjshare-drive-usage.ps1` and click `Edit`
<br/>4.) Edit the variable `$storjshareFolders` and set it to the folder path / drive path (make sure ends with semicolon (;)

```
Example:
    $storjshareFolders = "E:\storjshare;"
    $storjshareFolders += "F:\storjshare;"
```
<br/>5.) Save the file
<br/>6.) Double-click `run.bat`
<br/>7.) The report should display after some time with total disk usage and a summary of each of the folders' usage
<br/>
<br/>COMPATIBILITY:
<br/>   -PowerShell Version 2 or newer
<br/>   -Client OS: Windows 7 or newer
<br/>   -Server OS: Windows 2008 or newer
