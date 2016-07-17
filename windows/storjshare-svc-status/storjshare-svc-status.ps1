#Requires -Version 3
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Generates a report on current storjshare svc status and fixes the service if it is stopped
.DESCRIPTION
  Generates a report on current storjshare svc status and fixes the service if it is stopped

.INPUTS
  -silent - [optional] this will write everything to a log file and prevent the script from running pause commands.
  -runas - [optional] Runs the script as a service account
    -username username [required] Username of the account
    -password 'password' [required] Password of the account
   -noautoupdate
        -howoften - [optional] Days to check for updates (Default: Every day)
        -checktime - [optional] Time to check for updates (Default: 3:00am Local Time)
   -svcname - [optional] - Specifies the service name (Defualt it uses a wildcard of *storjshare-cli-*
.OUTPUTS
  Report of each folder's usage and total usage.
#>

#-----------------------------------------------------------[Parameters]------------------------------------------------------------

param(
    [Parameter(Mandatory=$false)]
    [SWITCH]$silent,

    [Parameter(Mandatory=$false)]
    [SWITCH]$runas,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$username,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$password,

    [Parameter(Mandatory=$false)]
    [SWITCH]$noautoupdate,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$svcname,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:total=0
$global:script_version="1.0"
$global:howoften="Daily"
$global:checktime="3am"
$global:runas=""
$global:username=""
$global:password=""
$global:noautoupdate=""

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$global:svcname = "*storjshare-cli*"
$log_path=$env:windir + '\Temp\storj\service'
$log_file=$log_path + '\svc_status.log'

$global:appdata=$env:appdata + '\' # (Default: %APPDATA%\) - runas overwrites this variable
$global:npm_path='' + $global:appdata + "npm\"

$windows_env=$env:windir
$work_directory='' + $windows_env + '\Temp\storj'
$save_dir=$work_directory + '\installs'
$storjshare_svc_status_install_log_path=$save_dir
$storjshare_svc_status_install_log_file=$storjshare_svc_status_install_log_path + '\automate_svc_status_install.log'; #outputs everything to a file if -silent is used, instead of the console

$limit = (Get-Date).AddDays(-1)

$automated_script_path=Split-Path -parent $PSCommandPath
$automated_script_path=$automated_script_path + '\'

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function handleParameters() {
    if(!(Test-Path -pathType container $storjshare_svc_status_install_log_path)) {
        New-Item $storjshare_svc_status_install_log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $storjshare_svc_status_install_log_path)) {
		ErrorOut "Log Directory $storjshare_svc_status_install_log_path failed to create, try it manually..."
	}

    if(Test-Path $storjshare_svc_status_install_log_file) {
        Remove-Item $storjshare_svc_status_install_log_file
    }

    if(!(Test-Path -pathType container $save_dir)) {
        New-Item $save_dir -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $save_dir)) {
		ErrorOut "Save Directory $save_dir failed to create, try it manually..."
	}

    # Delete files older than the $limit.
    Get-ChildItem -Path $log_path -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $limit } | Remove-Item -Force

    if($svcname) {
        $global:svcname=$svcname
    }

    #checks the silent parameter and if true, writes to log instead of console, also ignores pausing
    if($silent) {
        LogWrite "Logging to file $storjshare_cli_install_log_file"
    }
    else
    {
        $message="Logging to console"
        LogWrite $message
    }

    if ($runas) {
        $global:runas="true"

        if(!($username)) {
            ErrorOut -code $error_invalid_parameter "ERROR: Username not specified"
        } else {
            $global:username="$username"
        }

        if(!($password)) {
            ErrorOut -code $error_invalid_parameter "ERROR: Password not specified"
        } else {
            $global:password="$password"
        }

        $securePassword = ConvertTo-SecureString $global:password -AsPlainText -Force
        $global:credential = New-Object System.Management.Automation.PSCredential $global:username, $securePassword

        $appdata=GetUserEnvironment "%APPDATA%"
        $global:appdata=$appdata.Substring(0,$appdata.Length-1) + '\'

        $global:npm_path='' + $global:appdata + "npm\"

        LogWrite "Using Service Account: $global:username"
        LogWrite "Granting $global:username Logon As A Service Right"
        Grant-LogOnAsService $global:username
    }

    if($noautoupdate) {
        $global:noautoupdate="true"
    } else {
        if(!($howoften)) {
            $global:howoften=$global:howoften
        } else {
            $global:howoften=$howoften
        }

        if(!($checktime)) {
            $global:checktime=$global:checktime
        } else {
            $global:checktime=$checktime
        }

        LogWrite "Auto-update enabled to happen every $global:howoften day(s) at $global:checktime"
    }
}

function Grant-LogOnAsService{
param(
    [string[]] $users
    )
    #Get list of currently used SIDs 
    secedit /export /cfg "$storjshare_cli_install_log_path\tempexport.inf"
    $curSIDs = Select-String "$storjshare_cli_install_log_path\tempexport.inf" -Pattern "SeServiceLogonRight" 
    $Sids = $curSIDs.line 
    $sidstring = ""
    foreach($user in $users){
        $objUser = New-Object System.Security.Principal.NTAccount($user)
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        if(!$Sids.Contains($strSID) -and !$sids.Contains($user)){
            $sidstring += ",*$strSID"
        }
    }
    if($sidstring){
        $newSids = $sids + $sidstring
        LogWrite "New Sids: $newSids"
        $tempinf = Get-Content "$storjshare_cli_install_log_path\tempexport.inf"
        $tempinf = $tempinf.Replace($Sids,$newSids)
        Add-Content -Path "$storjshare_cli_install_log_path\tempimport.inf" -Value $tempinf
        secedit /import /db "$storjshare_cli_install_log_path\secedit.sdb" /cfg "$storjshare_cli_install_log_path\tempimport.inf" 
        secedit /configure /db "$storjshare_cli_install_log_path\secedit.sdb"
 
        gpupdate /force 
    }else{
        LogWrite "No new sids, skipping..."
    }
    del "$storjshare_cli_install_log_path\tempimport.inf" -force -ErrorAction SilentlyContinue
    del "$storjshare_cli_install_log_path\secedit.sdb" -force -ErrorAction SilentlyContinue
    del "$storjshare_cli_install_log_path\tempexport.inf" -force
}

function GetUserEnvironment([string]$env_var) {
	$filename = 'user_env.log';
	$save_path = '' + $storjshare_cli_install_log_path + '\' + $filename;

	if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
	    ErrorOut "Save directory $storjshare_cli_install_log_path does not exist";
	}

    $Arguments="/c ECHO $env_var"
    $proc = Start-Process "cmd.exe" -Credential $global:credential -Workingdirectory "$env:windir\System32" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow

    if(!(Test-Path $save_path)) {
        ErrorOut "cmd command $Arguments failed to execute...try manually running it..."
    }
    
    $results=(Get-Content -Path "$save_path")

    Remove-Item "$save_path"
    
    return $results
}

Function StatusWrite([string]$logstring) {
    $LogTime = Get-Date -Format s
    $logmessage="$logstring,""timestamp:""$LogTime"""
    if($logstring) {
        if(!(Test-Path -pathType container $log_path)) {

            New-Item $log_path -type directory -force | Out-Null

            if(!(Test-Path -pathType container $log_path)) {
		        ErrorOut "Log Directory $log_path failed to create, try it manually..."
	        }
	    }
        Add-content $log_file -value $logmessage
    }
}

Function LogWrite([string]$logstring,[string]$color) {
    $LogTime = Get-Date -Format "MM-dd-yyyy hh:mm:ss"
    $logmessage="["+$LogTime+"] "+$logstring
    if($silent) {
        if($logstring) {
            if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {

                New-Item $storjshare_cli_install_log_path -type directory -force | Out-Null

                if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
		            ErrorOut "Log Directory $storjshare_cli_install_log_path failed to create, try it manually..."
	            }
	        }
            Add-content $storjshare_cli_install_log_file -value $logmessage
        }
    } else {
        if(!$logstring) {
            $logmessage=$logstring
        }

        if($color) {
            write-host -fore $color $logmessage
        } else {
            write-host $logmessage
        }
    }
}

function ErrorOut([string]$message,[int]$code=0) {
    LogWrite -color Red $message    
    exit $code;
}

function storjshare_drive_usage_checkver([string]$script_ver) {
    LogWrite "Checking for Storj Script Version Environment Variable..."
    $env:STORJSHARE_SVC_STATUS_SCRIPT_VER = [System.Environment]::GetEnvironmentVariable("STORJSHARE_SVC_STATUS_SCRIPT_VER","Machine")
    if ($env:STORJSHARE_SVC_STATUS_SCRIPT_VER -eq $script_ver) {
    	LogWrite "STORJSHARE_SVC_STATUS_SCRIPT_VER Environment Variable $script_ver already matches, skipping..."
    } else {
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name STORJSHARE_SVC_STATUS_SCRIPT_VER -Value $script_ver -ErrorAction SilentlyContinue
        LogWrite "Storjshare Script Version Environment Variable Added: $script_ver"
    }
}

function autoupdate($howoften) {
    if(!($global:noautoupdate)) {

        Copy-Item "${automated_script_path}storjshare-svc-status.ps1" "$global:npm_path" -force -ErrorAction SilentlyContinue
        LogWrite "Script file copied to $global:npm_path"

        $Arguments="-NoProfile -NoLogo -Noninteractive -WindowStyle Hidden -ExecutionPolicy Bypass ""${global:npm_path}storjshare-svc-status.ps1"" -silent -noautoupdate"
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $Arguments
        $repeat = (New-TimeSpan -Minutes 10)
        $trigger = New-JobTrigger -Once -At (Get-Date).Date -RepeatIndefinitely -RepetitionInterval $repeat

        if($global:runas) {
                Register-ScheduledTask -Action $action -User $global:username -Password "$global:password" -Trigger $trigger -TaskName "storjshare Service Status Report" -Description "Generates Service Status Report" -RunLevel Highest
        } else {
                Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "storjshare Service Status Report" -Description "Generates Service Status Report" -RunLevel Highest
        }

        LogWrite "Scheduled Task Created"
    } else {
        LogWrite "No autoupdate specified skipping"
    }
}

function GetServiceStatus {
    param($ServiceName)
    
    $arrService = Get-Service -Name $ServiceName
    
    if ($arrService.Status -ne "Running") {
        Start-Service $ServiceName
        LogWrite "Starting Service"
    }

    if ($arrService.Status -eq "running") { 
        $log="$ServiceName,1"
    } else {
        $log="$ServiceName,0"
    }

    LogWrite $log
    StatusWrite $log
}

function CheckService($ServiceName) {
    $services=Get-Service -Name $ServiceName
    $services | ForEach-Object{GetServiceStatus $_.name}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

handleParameters

LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Generating storjshare-size Report"
LogWrite -color Cyan "Script Version: $global:script_version"
LogWrite -color Cyan "Github Site: https://github.com/Storj/storj-automation"
LogWrite -color Red "USE AT YOUR OWN RISK"
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Checking Service Status..."
LogWrite ""
CheckService $global:svcname
LogWrite ""
LogWrite -color Cyan "Reviewing Script Registry Version..."
storjshare_drive_usage_checkver $global:script_version
LogWrite -color Green "Script Registry Version Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Auto-Update Ability..."
autoupdate $global:howoften
LogWrite -color Green "Auto-Update Ability Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Completed storjshare-svc-status Report"
LogWrite -color Yellow "=============================================="
