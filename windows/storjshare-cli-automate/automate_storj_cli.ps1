#Requires -Version 3
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Automates the management of storjshare-cli for Windows only
.DESCRIPTION
  Automates the management of storjshare-cli for Windows only

  This checks for pre-req software
  Then it checks for storjshare-cli
  Then it updates storjshare-cli

  Examples:
  To deploy silently use the following command
  ./automate_storj_cli.ps1 -silent

  To install service use the following command
  ./automate_storj_cli.ps1 -installsvc -datadir C:\storjshare -storjpassword 4321

  To remove service use the following command
  ./automate_storj_cli.ps1 -removesvc

  To disable UPNP
  ./automate_storj_cli.ps1 -noupnp

    To run as a service account in silent mode, no upnp, auto reboot, and install a service
  ./automate_storj_cli.ps1 -silent -runas -username username -password password -noupnp -autoreboot -installsvc -datadir C:\storjshare -storjpassword 4321

.INPUTS
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
    -payaddr [storj addr] - [optional] Payment address STORJ wallet (Default: [blank; free])
    -tunconns [integer] - [optional] Number of allowed tunnel connections (Default: 3)
    -tunsvcport [port number] - [optional] Port number of Tunnel Service (Default: 0; random)
    -tunstart [port number] - [optional] Starting port number (Default: 0; random)
    -tunend [port number] - [optional] Ending port number (Default: 0; random)
   -noautoupdate
        -howoften - [optional] Days to check for updates (Default: Every day)
        -checktime - [optional] Time to check for updates (Default: 3:00am Local Time)
   -update - [optional] Performs an update only function and skips the rest
.OUTPUTS
  Return Codes (follows .msi standards) (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
#>

#-----------------------------------------------------------[Parameters]------------------------------------------------------------

param(
    [Parameter(Mandatory=$false)]
    [SWITCH]$silent,

    [Parameter(Mandatory=$false)]
    [SWITCH]$noupnp,

    [Parameter(Mandatory=$false)]
    [SWITCH]$installsvc,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$svcname,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$datadir,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$storjpassword,

    [Parameter(Mandatory=$false)]
    [SWITCH]$removesvc,

    [Parameter(Mandatory=$false)]
    [SWITCH]$runas,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$username,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$password,

    [Parameter(Mandatory=$false)]
    [SWITCH]$autoreboot,

    [Parameter(Mandatory=$false)]
    [SWITCH]$autosetup,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$publicaddr,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$svcport,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$nat,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$uri,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$loglvl,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$amt,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$payaddr,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$tunconns,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$tunsvcport,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$tunstart,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$tunend,

    [Parameter(Mandatory=$false)]
    [SWITCH]$noautoupdate,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$howoften,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$checktime,

    [Parameter(Mandatory=$false)]
    [SWITCH]$update,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:script_version="3.8" # Script version
$global:reboot_needed=""
$global:noupnp=""
$global:installsvc="true"
$global:svcname="storjshare-cli"
$global:storjpassword=""
$global:runas=""
$global:username=""
$global:password=""
$global:autoreboot=""
$global:noautoupdate=""
$global:howoften="Daily"
$global:checktime="3am"
$global:update=""
$global:return_code=$global:error_success #default success
$global:user_profile=$env:userprofile + '\' # (Default: %USERPROFILE%) - runas overwrites this variable
$global:appdata=$env:appdata + '\' # (Default: %APPDATA%\) - runas overwrites this variable
$global:npm_path='' + $global:appdata + "npm\"
$global:datadir=$global:user_profile + ".storjshare\" #Default: %USERPROFILE%\.storjshare
$global:storjshare_bin='' + $global:npm_path + "storjshare.cmd" # Default: storj-bridge location %APPDATA%\npm\storj-bridge.cmd" - runas overwrites this variable
$global:autosetup=""
$global:publicaddr="127.0.0.1" #Default 127.0.0.1
$global:svcport="4000" #Default to 4000
$global:nat="true" #Default true for storjshare
$global:uri="" #Default blank for storjshare
$global:loglvl="3" #Default 3 for storjshare
$global:amt="2GB" #default: 2GB for storjshare
$global:payaddr="" #Default none; aka farming for free; for storjshare
$global:tunconns="3" #Default 3
$global:tunsvcport="0" #Default 0; random
$global:tunstart="0" #Defualt 0; random
$global:tunend="0" #Default 0; random

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$windows_env=$env:windir
$work_directory='' + $windows_env + '\Temp\storj'
$save_dir=$work_directory + '\installs'
$storjshare_cli_install_log_path=$save_dir
$storjshare_cli_install_log_file=$storjshare_cli_install_log_path + '\automate_storjshare_cli.log'; #outputs everything to a file if -silent is used, instead of the console
$storjshare_cli_log_path=$work_directory + '\cli'
$global:storjshare_cli_log="$storjshare_cli_log_path\$global:svcname.log"

$gitforwindows_ver="2.8.3"  #   (Default: 2.8.3)

$nodejs_ver="4.4.5" #make sure to reference LTS branch version (Default: 4.4.5)

$python_ver="2.7.11" #currently only use version 2 branch (Default: 2.7.11)
$python_path = "C:\Python27\" #make sure ends with \ (Default: C:\Python27\)

$visualstudio_ver="2015" # currently only supports 2015 Edition (Default: 2015)
$visualstudio_dl="http://go.microsoft.com/fwlink/?LinkID=626924"  #  link to 2015 download   (Default: http://go.microsoft.com/fwlink/?LinkID=626924)

#Handles EXE Security Warnings
$Lowriskregpath ="HKCU:\Software\Microsoft\Windows\Currentversion\Policies\Associations"
$Lowriskregfile = "LowRiskFileTypes"
$LowRiskFileTypes = ".exe"

$nssm_ver="2.24" # (Default: 2.24)
$nssm_location="$windows_env\System32" # Default windows directory
$nssm_bin='' + $nssm_location + '\' + "nssm.exe" # (Default: %WINDIR%\System32\nssm.exe)

$error_success=0  #this is success
$error_invalid_parameter=87 #this is failiure, invalid parameters referenced
$error_install_failure=1603 #this is failure, A fatal error occured during installation (default error)
$error_success_reboot_required=3010  #this is success, but requests for reboot

$automatic_restart_timeout=30  #in seconds Default: 30

$automated_script_path=Split-Path -parent $PSCommandPath
$automated_script_path=$automated_script_path + '\'

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function handleParameters() {

    if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
        New-Item $storjshare_cli_install_log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
		ErrorOut "Log Directory $storjshare_cli_install_log_path failed to create, try it manually..."
	}

    if(!(Test-Path -pathType container $storjshare_cli_log_path)) {
        New-Item $storjshare_cli_log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $storjshare_cli_log_path)) {
		ErrorOut "Log Directory $storjshare_cli_log_path failed to create, try it manually..."
	}

    if(!(Test-Path -pathType container $save_dir)) {
        New-Item $save_dir -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $save_dir)) {
		ErrorOut "Save Directory $save_dir failed to create, try it manually..."
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

        $user_profile=GetUserEnvironment "%USERPROFILE%"
        $global:user_profile=$user_profile.Substring(0,$user_profile.Length-1) + '\'

        $appdata=GetUserEnvironment "%APPDATA%"
        $global:appdata=$appdata.Substring(0,$appdata.Length-1) + '\'

        $global:npm_path='' + $global:appdata + "npm\"
        $global:storjshare_bin='' + $global:npm_path + "storjshare.cmd" # Default: storjshare location %APPDATA%\npm\storjshare.cmd" - runas overwrites this variable

        $global:datadir=$global:user_profile + ".storjshare\"

        LogWrite "Using Service Account: $global:username"
        LogWrite "Granting $global:username Logon As A Service Right"
        Grant-LogOnAsService $global:username
    }

    if($update) {
        $global:update="true"
        LogWrite "Performing Update Only Function"
    } else {
        #checks for noupnp flag
        if ($noupnp) {
            $global:noupnp="true"
        }

        #checks for installsvc flag
        if ($global:installsvc) {
            $global:installsvc="true"

            if(!($svcname)) {
                $global:svcname="$global:svcname"
            } else {
                $global:svcname="$svcname"
            }

            $global:storjshare_cli_log="$storjshare_cli_log_path\$global:svcname.log"

            if(!($datadir)) {
                LogWrite "Using default storjshare datadir path: $datadir"
                $global:datadir="$global:datadir"
            } else {
                LogWrite "Using custom storjshare datadir path: $datadir"
                $global:datadir="$datadir"
            }

            if(!($storjpassword)) {
                if($silent) {
                    ErrorOut -code $global:error_invalid_parameter "ERROR: Service Password not specified"
                } else {
                    if(!(Test-Path -pathType container $global:datadir)) {
                        $global:storjpassword = GET-RANDOM
                        LogWrite "We generated a password for storjshare since one was not provided"
                        LogWrite "Your Password Is:"
                        LogWrite -Color Cyan "$global:storjpassword"
                        LogWrite -Color Red "Write this down; you will need it to type into storjshare when asked!!!!"
                        Sleep -s 2
                        Write-Host "Press any key to continue ..."
                        $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                }
            } else {
                $global:storjpassword="$storjpassword"
            }
        }

        #checks for removesvc flag
        if ($removesvc) {
            $global:removesvc="true"

            if(!($svcname)) {
                $global:svcname="$storshare_svcname"
            } else {
                $global:svcname="$svcname"
            }

            $global:storjshare_cli_log="$storjshare_cli_log_path\$global:svcname.log"
        }

        if($autoreboot) {
            LogWrite "Will auto-reboot if needed"
            $global:autoreboot="true"
        }

        if ($autosetup) {
            $global:autosetup="true"

            if(!($datadir)) {
                LogWrite "Using default storjshare datadir path: $datadir"
                $global:datadir="$global:datadir"
            } else {
                LogWrite "Using custom storjshare datadir path: $datadir"
                $global:datadir="$datadir"
            }

            if(!($storjpassword)) {
                ErrorOut -code $global:error_invalid_parameter "ERROR: storjshare Password not specified"
            } else {
                $global:storjpassword="$storjpassword"
            }

            if(!($publicaddr)) {
                $global:publicaddr="$global:publicaddr"
            } else {
                $global:publicaddr=$publicaddr.Replace("[THIS]",$env:computername)
            }

            if(!($svcport)) {
                $global:svcport="$global:svcport"
            } else {
                $global:svcport="$svcport"
            }

            if(!($nat)) {
                $global:nat="$global:nat"
            } else {
                $global:nat="$nat"
            }

            if(!($amt)) {
                $global:amt="$global:amt"
            } else {
                $global:amt="$amt"
            }

            if(!($uri)) {
                $global:uri="$global:uri"
            } else {
                $global:uri="$uri"
            }

            if(!($loglvl)) {
                $global:loglvl="$global:loglvl"
            } else {
                $global:loglvl="$loglvl"
            }

            if(!($payaddr)) {
                $global:payaddr="$global:payaddr"
            } else {
                $global:payaddr="$payaddr"
            }

            if(!($tunconns)) {
                $global:tunconns="$global:tunconns"
            } else {
                $global:tunconns="$tunconns"
            }

            if(!($tunsvcport)) {
                $global:tunsvcport="$global:tunsvcport"
            } else {
                $global:tunsvcport="$tunsvcport"
            }

            if(!($tunstart)) {
                $global:tunstart="$global:tunstart"
            } else {
                $global:tunstart="$tunstart"
            }

            if(!($tunend)) {
                $global:tunend="$global:tunend"
            } else {
                $global:tunend="$tunend"
            }
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

            LogWrite "Auto-update disabled to happen every $global:howoften day(s) at $global:checktime"
        }
    }

    #checks for unknown/invalid parameters referenced
    if ($other_args) {
        ErrorOut -code $global:error_invalid_parameter "ERROR: Unknown arguments: $other_args"
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

function ErrorOut([string]$message,[int]$code=$error_install_failure) {
    LogWrite -color Red $message
    
    if($silent) {
    	LogWrite -color Red "Returning Error Code: $code"
    }
    
    exit $code;
}

function GitForWindowsCheck([string]$version) {
    LogWrite "Checking if Git for Windows is installed..."
    If(!(Get-IsProgramInstalled "Git")) {
        LogWrite "Git for Windows $version is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='-32-bit'
        } else {
            $arch="64-bit"
            $arch_ver='-64-bit'
        }

	    $filename = 'Git-' + $version + $arch_ver + '.exe';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='https://github.com/git-for-windows/git/releases/download/v' + $version + '.windows.1/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist"
	    }

        LogWrite "Downloading Git for Windows ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "Git for Windows downloaded"

	    LogWrite "Installing Git for Windows $version..."
        $Arguments = "/SILENT /COMPONENTS=""icons,ext\reg\shellhere,assoc,assoc_sh"""
	    InstallEXE $save_path $Arguments
        
        If(!(Get-IsProgramInstalled "Git")) {
           ErrorOut "Git for Windows did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "Git for Windows Installed Successfully"
    }
    else
    {
        LogWrite "Git for Windows is already installed."
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "Git" )
        if(!$installed_version) {
            ErrorOut "Git for Windows Version is Unknown - Error"
        }

        $result = CompareVersions $installed_version $gitforwindows_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match Git for Windows version (Installed Version: $installed_version / Requested Version: $gitforwindows_ver)"
        }

        if($result -eq 0)
        {
            LogWrite "Git for Windows is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Git for Windows is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Git for Windows is out of date."
            
            LogWrite -Color Cyan "Git for Windows $installed_version will be updated to $gitforwindows_ver..."
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver='-32-bit'
            } else {
                $arch="64-bit"
                $arch_ver='-64-bit'
            }

    	    $filename = 'Git-' + $gitforwindows_ver + $arch_ver + '.exe';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='https://github.com/git-for-windows/git/releases/download/v' + $gitforwindows_ver + '.windows.1/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist"
	        }

            LogWrite "Downloading Git for Windows ($arch) $gitforwindows_ver..."
            DownloadFile $url $save_path
            LogWrite "Git for Windows downloaded"

	        LogWrite "Installing Git for Windows $gitforwindows_ver..."
            $Arguments = "/SILENT /COMPONENTS=""icons,ext\reg\shellhere,assoc,assoc_sh"""
	        InstallEXE $save_path $Arguments
        
            If(!(Get-IsProgramInstalled "Git")) {
                ErrorOut "Git for Windows did not complete installation successfully...try manually updating it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Git for Windows Updated Successfully"
            $installed_version = $gitforwindows_ver            
        }

        LogWrite -color Green "Git for Windows Installed Version: $installed_version"
    }
}

function NodejsCheck([string]$version) {
    LogWrite "Checking if Node.js is installed..."
    If(!(Get-IsProgramInstalled "Node.js")) {
        LogWrite "Nodejs $version is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='-x86'
        } else {
            $arch="64-bit"
            $arch_ver='-x64'
        }

	    $filename = 'node-v' + $version + $arch_ver + '.msi';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='https://nodejs.org/dist/v' + $version + '/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist";
	    }

        LogWrite "Downloading Node.js LTS ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "Nodejs downloaded"

	    LogWrite "Installing Node.js LTS $version..."
	    InstallMSI $save_path
        
        If(!(Get-IsProgramInstalled "Node.js")) {
           ErrorOut "Node.js did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "Node.js Installed Successfully"
    }
    else
    {
        LogWrite "Node.js already installed."
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "Node.js" )
        if(!$version) {
            ErrorOut "Node.js Version is Unknown - Error"
        }

        $result = CompareVersions $installed_version $nodejs_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match Node.js version (Installed Version: $installed_version / Requested Version: $nodejs_ver)"
        }

        if($result -eq 0)
        {
            LogWrite "Node.js is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Node.js is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Node.js is out of date."
            LogWrite -Color Cyan "Node.js $installed_version will be updated to $nodejs_ver..."
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver='-x86'
            } else {
                $arch="64-bit"
                $arch_ver='-x64'
            }

	        $filename = 'node-v' + $nodejs_ver + $arch_ver + '.msi';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='https://nodejs.org/dist/v' + $nodejs_ver + '/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist";
	        }

            LogWrite "Downloading Node.js LTS ($arch) $nodejs_ver..."
            DownloadFile $url $save_path
            LogWrite "Nodejs downloaded"

	        LogWrite "Installing Node.js LTS $nodejs_ver..."
	        InstallMSI $save_path
        
            If(!(Get-IsProgramInstalled "Node.js")) {
               ErrorOut "Node.js did not complete installation successfully...try manually updating it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Node.js Updated Successfully"
            $installed_version = $nodejs_ver
        }

        LogWrite -color Green "Node.js Installed Version: $installed_version"
    }
    LogWrite "Checking for Node.js NPM Environment Path..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    if ($PathasArray -contains $global:npm_path -or $PathAsArray -contains $global:npm_path+'\') {
    	LogWrite "Node.js NPM Environment Path $global:npm_path already within System Environment Path, skipping..."
    } else {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue).Path
        $NewPath=$OldPath+';'+$global:npm_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue
        LogWrite "Node.js NPM Environment Path Added: $global:npm_path"
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
        $global:reboot_needed="true"
    }
}

function PythonCheck([string]$version) {
    LogWrite "Checking if Python is installed..."
    If(!(Get-IsProgramInstalled "Python")) {
        LogWrite "Python $version is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver=''
        } else {
            $arch="64-bit"
            $arch_ver='.amd64'
        }

	    $filename = 'python-' + $version + $arch_ver + '.msi';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='http://www.python.org/ftp/python/' + $version + '/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist";
	    }

        LogWrite "Downloading Python ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "Python downloaded"

	    LogWrite "Installing Python $version..."
	    InstallMSI $save_path
        
        If(!(Get-IsProgramInstalled "Python")) {
           ErrorOut "Python did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "Python Installed Successfully"
    }
    else
    {
        LogWrite "Python already installed."
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "Python" )
        $installed_version = $installed_version.Substring(0,$installed_version.Length-3)
        if(!$installed_version) {
            ErrorOut "Python Version is Unknown - Error"
        }

        if($installed_version.Split(".")[0] -gt "2" -Or $installed_version.Split(".")[0] -lt "2") {
            ErrorOut "Python version not supported.  Please remove all versions of Python and run the script again."
        }

        $result = CompareVersions $installed_version $python_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match Python version (Installed Version: $installed_version / Requested Version: $python_ver)"
        }

        if($result -eq 0)
        {
            LogWrite "Python is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Python is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Python is out of date."
            LogWrite -Color Cyan "Python $installed_version will be updated to $python_ver..."
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver=''
            } else {
                $arch="64-bit"
                $arch_ver='.amd64'
            }

	        $filename = 'python-' + $python_ver + $arch_ver + '.msi';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='http://www.python.org/ftp/python/' + $python_ver + '/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist";
	        }

            LogWrite "Downloading Python ($arch) $python_ver..."
            DownloadFile $url $save_path
            LogWrite "Python downloaded"

	        LogWrite "Installing Python $python_ver..."
	        InstallMSI $save_path
        
            If(!(Get-IsProgramInstalled "Python")) {
               ErrorOut "Python did not complete installation successfully...try manually installing it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Python Updated Successfully"
            $installed_version=$python_ver
        }

        LogWrite -color Green "Python Installed Version: $installed_version"
    }

    LogWrite "Checking for Python Environment Path..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    if ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        LogWrite "Python Environment Path $python_path already within System Environment Path, skipping..."
    } else {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue).Path
        $NewPath=$OldPath+';'+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue
        LogWrite "Python Environment Path Added: $python_path"
        $global:reboot_needed="true"
    }

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    $python_path=$python_path+"Scripts\";
    if ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        LogWrite "Python Environment Path $python_path already within System Environment Path, skipping..."
    } else {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue).Path
        $NewPath=$OldPath+';'+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
        LogWrite "Python Environment Path Added: $python_path"
        $global:reboot_needed="true"
    }
}

function VisualStudioCheck([string]$version, [string]$dl_link) {
    LogWrite "Checking if Visual Studio Community Edition is installed..."
    If(!(Get-IsProgramInstalled "Microsoft Visual Studio Community")) {
        LogWrite "Visual Studio Community $version Edition is not installed."
        $filename = 'vs_community_ENU.exe';
	    $save_path = '' + $save_dir + '\' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist";
	    }

        LogWrite "Downloading Visual Studio Community $version Edition..."
        FollowDownloadFile $dl_link $save_path
        LogWrite "Visual Studio Community $version Edition downloaded"

	    LogWrite "Installing Visual Studio Community $version Edition..."
        $Arguments = "/InstallSelectableItems NativeLanguageSupport_Group /NoRestart /Passive"
	    InstallEXE $save_path $Arguments

        If(!(Get-IsProgramInstalled "Microsoft Visual Studio Community")) {
           ErrorOut "Visual Studio Community $version Edition did not complete installation successfully...try manually installing it..."
        }
        
        $global:reboot_needed="true"

        LogWrite -color Green "Visual Studio Community $version Edition Installed"
    }
    else
    {
        LogWrite "Visual Studio Community $version Edition already installed."
        LogWrite "Checking version..."

        $version_check = Get-ProgramVersion( "Microsoft Visual Studio Community" )
        if(!$version_check) {
            ErrorOut "Visual Studio Community Edition Version is Unknown - Error"
        }

        LogWrite -color Green "Visual Studio Community $version Edition Installed"
    }

    LogWrite "Checking for Visual Studio Community $version Edition Environment Variable..."
    $env:GYP_MSVS_VERSION = [System.Environment]::GetEnvironmentVariable("GYP_MSVS_VERSION","Machine")
    If ($env:GYP_MSVS_VERSION) {
        LogWrite "Visual Studio Community $version Edition Environment Variable (GYP_MSVS_VERSION - $env:GYP_MSVS_VERSION) is already set, skipping..."
    }
    else
    {
        [Environment]::SetEnvironmentVariable("GYP_MSVS_VERSION", $version, "Machine")
        $env:GYP_MSVS_VERSION = [System.Environment]::GetEnvironmentVariable("GYP_MSVS_VERSION","Machine")
        LogWrite "Visual Studio Community $version Edition Environment Variable Added: GYP_MSVS_VERSION - $env:GYP_MSVS_VERSION"
        $global:reboot_needed="true"
    }
}

function storjshare-cliCheck() {
    LogWrite "Checking if storjshare-cli is installed..."
    $Arguments = "list -g"
    $output=(UseNPM $Arguments| Where-Object {$_ -like '*storjshare-cli*'})

    #write npm logs to log file if in silent mode
    if($silent) {
        LogWrite "npm $Arguments results"
        Add-content $storjshare_cli_install_log_file -value $output
    }

    if (!$output.Length -gt 0) {
        LogWrite "storjshare-cli is not installed."
        LogWrite "Installing storjshare-cli (latest version released)..."

        $Arguments = "install -g storjshare-cli"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $storjshare_cli_install_log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storjshare-cli did not complete installation successfully...try manually installing it..."
        }

        LogWrite -color Green "storjshare-cli Installed Successfully"
    }
    else
    {
        LogWrite "storjshare-cli already installed."

        LogWrite "Stopping $global:svcname service (if applicable)"

        Stop-Service $global:svcname -ErrorAction SilentlyContinue
        $services=Get-Service -Name *storjshare-cli*
        $services | ForEach-Object{Stop-Service $_.name -ErrorAction SilentlyContinue}

        if(Test-Path $global:storjshare_cli_log) {
            LogWrite "Removing Log file: $global:storjshare_cli_log"
        }

        if(Test-Path $storjshare_cli_log_path) {
            LogWrite "Removing Logs files $storjshare_cli_log_path"
            Remove-Item "$storjshare_cli_log_path\*" -force
        }

        LogWrite -color Cyan "Performing storjshare-cli Update..."

        #$Arguments = "update -g storjshare-cli"
        $Arguments = "install -g storjshare-cli"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $storjshare_cli_install_log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storjshare-cli did not complete update successfully...try manually updating it..."
        }
        
        LogWrite -color Green "storjshare-cli Update Completed"

        LogWrite -color Cyan "Checking storjshare-cli version..."

        $pos=$output.IndexOf("storjshare-cli@")

        $version = $output.Substring($pos+15)
        if(!$version) {
            ErrorOut "storjshare-cli Version is Unknown - Error"
        }

        $services=Get-Service -Name *storjshare-cli*
        $services | ForEach-Object{Start-Service -Name $_.name -ErrorAction SilentlyContinue}
        Start-Service -Name $global:svcname -ErrorAction SilentlyContinue

        LogWrite -color Green "storjshare-cli Installed Version: $version"
    }
}

function Get-IsProgramInstalled([string]$program) {
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    return $x86 -or $x64;
}

function Get-ProgramVersion([string]$program) {
    $x86 = ((Get-ChildItem  -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } |
        Select-Object { $_.GetValue( "DisplayVersion" ) }  )

    $x64 = ((Get-ChildItem  -ErrorAction SilentlyContinue "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } |
        Select-Object { $_.GetValue( "DisplayVersion" ) }  )

    if ($x86) {
        $version = $x86 -split "="
        $version = $version[1].Split("}")[0]
    } elseif ($x64)  {
        $version = $x64 -split "="
        $version = $version[1].Split("}")[0]
    } else {
        $version = ""
    }

    return $version;
}

function DownloadFile([string]$url, [string]$targetFile) {
	if((Test-Path $targetFile)) {
	    LogWrite "$targetFile exists, using this download";
	} else {
        $uri = New-Object "System.Uri" "$url"
        $request = [System.Net.HttpWebRequest]::Create($uri)
        $request.set_Timeout(15000) #15 second timeout
        $response = $request.GetResponse()
        $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
        $responseStream = $response.GetResponseStream()
        $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
        $buffer = new-object byte[] 10KB
        $count = $responseStream.Read($buffer,0,$buffer.length)
        $downloadedBytes = $count
        while ($count -gt 0) {
            $targetStream.Write($buffer, 0, $count)
            $count = $responseStream.Read($buffer,0,$buffer.length)
            $downloadedBytes = $downloadedBytes + $count
            Write-Progress -activity "Downloading file '$($url.split('/') | Select -Last 1)'" -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength)  * 100)
        }
        Write-Progress -activity "Finished downloading file '$($url.split('/') | Select -Last 1)'"
        $targetStream.Flush()
        $targetStream.Close()
        $targetStream.Dispose()
        $responseStream.Dispose()
    }
}

function FollowDownloadFile([string]$url, [string]$targetFile) {
	if((Test-Path $targetFile)) {
	    LogWrite "$targetFile exists, using this download";
	} else {
        $webclient = New-Object System.Net.WebClient
        $webclient.DownloadFile($url,$targetFile)
    }
}

function AddLowRiskFiles() {
	New-Item -Path $Lowriskregpath -Erroraction SilentlyContinue | Out-Null
	New-ItemProperty $Lowriskregpath -Name $Lowriskregfile -Value $LowRiskFileTypes -PropertyType String -ErrorAction SilentlyContinue | Out-Null
}

function RemoveLowRiskFiles() {
	Remove-ItemProperty -Path $Lowriskregpath -Name $Lowriskregfile -ErrorAction SilentlyContinue
}

function InstallEXE([string]$installer, [string]$Arguments) {
	Unblock-File $installer
	AddLowRiskFiles
	Start-Process "`"$installer`"" -ArgumentList $Arguments -Wait -NoNewWindow
	RemoveLowRiskFiles
}

function InstallMSI([string]$installer) {
	$Arguments = @()
	$Arguments += "/i"
	$Arguments += "`"$installer`""
	$Arguments += "ALLUSERS=`"1`""
	$Arguments += "/passive"
	$Arguments += "/norestart"

	Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow
}

function UseNPM([string]$Arguments) {
	$filename = 'npm_output.log';
	$save_path = '' + $storjshare_cli_install_log_path + '\' + $filename;

	$filename_err = 'npm_output_err.log';
	$save_path_err = '' + $storjshare_cli_install_log_path + '\' + $filename_err;
	if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
	    ErrorOut "Log directory $storjshare_cli_install_log_path does not exist";
	}

	if(!(Test-Path -pathType container $global:npm_path)) {
	    New-Item $global:npm_path -type directory -force | Out-Null
	}

    if($global:runas) {
        $proc = Start-Process "npm" -Credential $global:credential -WorkingDirectory "$global:npm_path" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -RedirectStandardError "$save_path_err"
    } else {
        $proc = Start-Process "npm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -RedirectStandardError "$save_path_err"
    }

    Start-Sleep -s 5
    $processnpm=Get-Process | Where-Object { $_.MainWindowTitle -like '*npm*' } | select -expand id
    
    try
    {
        Wait-Process -Id $processnpm -Timeout 600 -ErrorAction SilentlyContinue
    }
    catch
    {
        LogWrite ""
    }
    
    if(!(Test-Path $save_path) -or !(Test-Path $save_path_err)) {
        ErrorOut "npm command $Arguments failed to execute...try manually running it..."
    }
    
    $results=(Get-Content -Path "$save_path")
    $results+=(Get-Content -Path "$save_path_err")

    Remove-Item "$save_path"
    Remove-Item "$save_path_err"

    return $results
}

function CheckRebootNeeded() {
	if($global:reboot_needed) {
        if((!$silent) -or (!$global:autoreboot)) {
            LogWrite -color Red "=============================================="
            LogWrite -color Red "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"
            LogWrite -color White "After the reboot, re-launch this script to complete the installation"
            ErrorOut -code $error_success_reboot_required "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"
        } else {
            LogWrite -color Red "=============================================="
            LogWrite -color Red "Initiating Auto-Reboot in $automatic_restart_timeout seconds"
            Restart-Computer -Wait $automatic_restart_timeout
            ErrorOut -code $error_success_reboot_required "~~~Automatically Rebooting in $automatic_restart_timeout seconds~~~"
        } 
    } else {
        LogWrite -color Green "No Reboot Needed, continuing on with script"
    }
}

function CompareVersions([String]$version1,[String]$version2) {
    $ver1 = $version1.Split(".")
    $ver2 = $version2.Split(".")
    if($ver1.Count -ne $ver2.Count) {
        return -2
    }
    for($i=0;$i -lt $ver1.count;$i++) {
        if($($ver1[$i]) -ne $($ver2[$i])) {
            if($($ver1[$i]) -lt $($ver2[$i])) {
                return -1
            } else {
                return 1
            }
        }
    }
    return 0
}

function ModifyService([string]$svc_name, [string]$svc_status) {
    Set-Service $svc_name -startuptype $svc_status   
}

function ChangeLogonService([string]$svc_name, [string]$username, [string]$password) {
    $LocalSrv = Get-WmiObject Win32_service -filter "name='$svc_name'"
    $LocalSrv.Change($null,$null,$null,$null,$null,$false,$username,$password)
    LogWrite "Changed Service $svc_name to Logon As $username"
}
function EnableUPNP() {
    LogWrite -color Cyan "Enabling UPNP..."

    #DNS Client
    ModifyService "Dnscache" "Automatic"

    #Function Discovery Resource Publication
    ModifyService "FDResPub" "Manual"

    #SSDP Discovery
    ModifyService "SSDPSRV" "Manual"

    #UPnP Device Host
    ModifyService "upnphost" "Manual"

	$results=SetUPNP "Yes"

    if($results -eq 0) {
        ErrorOut "Enabling UPNP failed to execute...try manually enabling UPNP..."
    } else {
        LogWrite -color Green "UPNP has been successfully enabled"
    }
}

function DisableUPNP() {
    LogWrite -color Cyan "Disabling UPNP..."

    ModifyService "Dnscache" "Automatic"
    ModifyService "FDResPub" "Manual"
    ModifyService "SSDPSRV" "Disabled"
    ModifyService "upnphost" "Disabled"

	$results=SetUPNP "No"

    if($results -eq 0) {
        ErrorOut "Disabling UPNP failed to execute...try manually disabling UPNP..."
    } else {
        LogWrite -color Green "UPNP has been successfully disabled"
    }
}

function SetUPNP([string]$upnp_set) {
	$filename = 'upnp_output.log';
	$save_path = '' + $storjshare_cli_install_log_path + '\' + $filename;

	if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
	    ErrorOut "Log directory $storjshare_cli_install_log_path does not exist";
	}
	
    $Arguments="advfirewall firewall set rule group=`"Network Discovery`" new enable=$($upnp_set)"
    $proc = Start-Process "netsh" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow

    if(!(Test-Path $save_path)) {
        ErrorOut "netsh command $Arguments failed to execute...try manually running it..."
    }
    
    $results=(Get-Content -Path "$save_path") | Where-Object {$_ -like '*Ok*'}

    Remove-Item "$save_path"
    
    if($results.Length -eq 0) {
        return 0
    }

    return 1
}

function CheckUPNP() {
    if(!($global:update)) {
        LogWrite "Checking UPNP Flag..."
        if($global:noupnp) {
            DisableUPNP
        } else {
            EnableUPNP
        }
    } else {
        LogWrite "Skipping UPNP checks, Update function flagged..."
    }
}

function CheckService([string]$svc_name) {
    write-host "Checking if $svc_name Service is installed..."
    if (Get-Service $svc_name -ErrorAction SilentlyContinue) {
        return 1
    } else {
        return 0
    }
}

function RemoveService([string]$svc_name) {
    LogWrite "Checking for service: $svc_name"
    if(CheckService $svc_name -eq 1) {
        Stop-Service $svc_name -ErrorAction SilentlyContinue
        $serviceToRemove = Get-WmiObject -Class Win32_Service -Filter "name='$svc_name'"
        $serviceToRemove.delete()
        if(CheckService $svc_name -eq 1) {
            ErrorOut "Failed to remove $svc_name"
        } else {
            LogWrite "Service $svc_name successfully removed"
        }
    } else {
        LogWrite "Service $svc_name is not installed, skipping removal..."
    }
}

function UseNSSM([string]$Arguments) {
	$filename = 'nssm_output.log';
	$save_path = '' + $storjshare_cli_install_log_path + '\' + $filename;
	if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
	    ErrorOut "Save directory $storjshare_cli_install_log_path does not exist";
	}
	
    $proc = Start-Process "nssm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow

    if(!(Test-Path $save_path)) {
        ErrorOut "nssm command $Arguments failed to execute..."
    }
    
    $results=(Get-Content -Path "$save_path")
    Remove-Item "$save_path"
    
    return $results
}

function Installnssm([string]$save_location,[string]$arch) {
    if(Test-Path $save_location) {
        LogWrite "Checking for $save_location"

        $filename=Split-Path $save_location -leaf
        $filename=$filename.Substring(0,$filename.Length-4)
        $extracted_folder="$save_dir\$filename"
        if(Test-Path -pathType container $extracted_folder) {
		    LogWrite "Skipping extraction...extracted folder already exists"
	    } else {
            LogWrite "Extracting NSSM zip"
            Add-Type -assembly "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory($save_location, $save_dir)
            LogWrite "Extracted NSSM successfully"
        }

        LogWrite "Placing NSSM into $nssm_location"
        Copy-Item "$extracted_folder\$arch\nssm.exe" "$nssm_location"

        if(!(Test-Path "$nssm_location\nssm.exe")) {
            ErrorOut "Failed to place NSSM at $nssm_location"
        }

        LogWrite "NSSM Placed Successfully"
    } else {
        ErrorOut "NSSM installation file does not exist at: $save_location"
    }
}

function nssmCheck([string]$version) {
    if($global:installsvc -or $global:removesvc) {
        LogWrite "Checking if NSSM is installed..."

	    if(!(Test-Path $nssm_bin)) {
            LogWrite "NSSM is not installed."
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver='win32'
            } else {
                $arch="64-bit"
                $arch_ver='win64'
            }

	        $filename = 'nssm-' + $version + '.zip';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='https://nssm.cc/release/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist"
	        }

            LogWrite "Downloading NSSM $version..."
            DownloadFile $url $save_path
            LogWrite "NSSM downloaded"

            LogWrite "Installing NSSM $version..."
            Installnssm $save_path $arch_ver

            LogWrite -color Green "NSSM Installed Successfully"
        } else {
             LogWrite -color Green "NSSM already installed"
        }

        if(!($global:update)) {
            LogWrite "Checking for $global:svcname to see if it exists"
            
            if(!(CheckService $global:svcname)) {
                if($global:installsvc) {

                    LogWrite "Checking if storjshare-cli data directory exists..."
	                if(!(Test-Path -pathType container $global:datadir)) {
	                    ErrorOut "sorjshare-cli directory $global:datadir does not exist, you may want to setup storjshare-cli first.";
	                }

                    LogWrite "Checking if storjshare-cli log directory exists..."
	                if(!(Test-Path -pathType container $storjshare_cli_log_path)) {
	                    ErrorOut "storjshare-cli log directory $storjshare_cli_log_path does not exist, you may want to setup storjshare-cli first.";
	                }

                    LogWrite "Installing service $global:svcname"
                    $Arguments="install $global:svcname $storjshare_bin start --datadir $global:datadir --password $global:storjpassword >> $global:storjshare_cli_log"
                    $results=UseNSSM $Arguments
                    if(CheckService($global:svcname)) {
                        LogWrite -color Green "Service $global:svcname Installed Successfully"
                    } else {
                        ErrorOut "Failed to install service $global:svcname"
                    }

                    if($global:runas) {
                        ChangeLogonService -svc_name $global:svcname -username ".\$global:username" -password $global:password
                    }
                }
                ModifyService "$global:svcname" "Automatic"
                LogWrite "Starting $global:svcname service..."
                Start-Service $global:svcname -ErrorAction SilentlyContinue
            } else {
                LogWrite "Service already exists, skipping..."
                Start-Service $global:svcname -ErrorAction SilentlyContinue
            }
        } else {
            LogWrite "Skipping service functions, in update mode"
        }
    }
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

function storjshare-enterdata($processid, [string] $command) {
    [Microsoft.VisualBasic.Interaction]::AppActivate($processid)
    Start-Sleep -s 1
    [System.Windows.Forms.SendKeys]::SendWait("$command{ENTER}")
    Start-Sleep -s 2
}

function setup-storjshare() {
    if(!($global:update)) {
	    if(!(Test-Path -pathType container $global:datadir)) {
            if($global:autosetup) {
                if(($global:storjpassword) -AND ($global:datadir)) {
	                $filename = 'storjshare_output.log';
	                $save_path = '' + $storjshare_cli_install_log_path + '\' + $filename;
	                if(!(Test-Path -pathType container $storjshare_cli_install_log_path)) {
	                    ErrorOut "Save directory $storjshare_cli_install_log_path does not exist";
	                }

                    LogWrite "storjshare directory $global:datadir does not exist"
                    LogWrite "Performing storjshare Setup in this directory"

                    add-type -AssemblyName microsoft.VisualBasic
                    add-type -AssemblyName System.Windows.Forms

                    LogWrite "Starting storjshare key sequence. Please wait for the dialog to close as this may take a couple minutes."
                    Start-Sleep -s 2

                    $Arguments="setup --datadir $global:datadir"
                    
                    if($global:runas) {
                        $proc = Start-Process "storjshare" -Credential $global:credential -WorkingDirectory "$global:npm_path" -ArgumentList $Arguments -RedirectStandardOutput "$save_path"
                    } else {
                        $proc = Start-Process "storjshare" -ArgumentList $Arguments -RedirectStandardOutput "$save_path"
                    }

                    if(!(Test-Path $save_path)) {
                        ErrorOut "storjshare command $Arguments failed to execute..."
                    }

                    Start-Sleep -s 3
                    $processstorjshare=Get-Process | Where-Object { $_.MainWindowTitle -like '*\System32\cmd.exe*' } | select -expand id

                    #public ip / hostname (default: 127.0.0.1)
                    storjshare-enterdata -processid $processstorjshare -command "$global:publicaddr"

                    #TCP port number service should use (default: 4000)
                    storjshare-enterdata -processid $processstorjshare -command "$global:svcport"

                    #Use NAT traversal (default: true)
                    storjshare-enterdata -processid $processstorjshare -command "$global:nat"

                    #URI of known seed (default: leave blank)
                    storjshare-enterdata -processid $processstorjshare -command "$global:uri"

                    #Enter path to store configuration (hit enter given argument)
                    storjshare-enterdata -processid $processstorjshare -command ""

                    #Log Level (default 3)
                    storjshare-enterdata -processid $processstorjshare -command "$global:loglvl"

                    #Amount of storage to use (default 2GB)
                    storjshare-enterdata -processid $processstorjshare -command "$global:amt"

                    #Payment Address  (default blank)
                    storjshare-enterdata -processid $processstorjshare -command "$global:payaddr"

                    #telemetry (force true and hit enter)
                    storjshare-enterdata -processid $processstorjshare -command "true"

                    #number of tunnel connections (default 3)
                    storjshare-enterdata -processid $processstorjshare -command "$global:tunconns"

                    #TCP port tunnel service (default 0 - random)
                    storjshare-enterdata -processid $processstorjshare -command "$global:tunsvcport"

                    #TCP start tunnel port (default 0 - random)
                    storjshare-enterdata -processid $processstorjshare -command "$global:tunstart"

                    #TCP end tunnel port (default port 0 - random)
                    storjshare-enterdata -processid $processstorjshare -command "$global:tunend"

                    #Path encrypted files (hit enter given argument)
                    storjshare-enterdata -processid $processstorjshare -command ""

                    #password to protect data (if none entered by user fail)
                    storjshare-enterdata -processid $processstorjshare -command "$global:storjpassword"
        
                    $results=(Get-Content -Path "$save_path") | Where-Object {$_ -like '*error*'}

                    if($results) {
                        ErrorOut "storjshare command $Arguments failed to execute..."
                    }

                    Remove-Item "$save_path"
                } else {
                    LogWrite "Missing required parameters; skipping setup..."
                }
            } else {
                LogWrite "Manually going through setup"
                LogWrite "You will be prompted by storjshare to enter various values"
                LogWrite -Yellow "Any questions around these values can be answered on https://github.com/Storj/storjshare-cli"

                $Arguments="setup --datadir $global:datadir"
                $proc = Start-Process "storjshare" -ArgumentList $Arguments -Wait

                LogWrite "Completed entering storjshare values...moving on"
            }

            LogWrite "Starting $global:svcname service..."
            Start-Service $global:svcname -ErrorAction SilentlyContinue
        }
        else
        {
            LogWrite "Skipping storjshare setup; data setup files exist..."
        }
    } else {
        LogWrite "Skipping setup check, in update mode..."
        $services=Get-Service -Name *storjshare-cli*
        $services | ForEach-Object{
            $service=$_.name
            Remove-Item "$storjshare_cli_log_path\$service.log"
            Start-Service -Name $service -ErrorAction SilentlyContinue
        }
        LogWrite "Re-started services"
    }
}

function storjshare_cli_checkver([string]$script_ver) {
    LogWrite "Checking for Storj Script Version Environment Variable..."
    $env:STORJSHARE_SCRIPT_VER = [System.Environment]::GetEnvironmentVariable("STORJSHARE_SCRIPT_VER","Machine")
    if ($env:STORJSHARE_SCRIPT_VER -eq $script_ver) {
    	LogWrite "STORJSHARE_SCRIPT_VER Environment Variable $script_ver already matches, skipping..."
    } else {
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name STORJSHARE_SCRIPT_VER -Value $script_ver -ErrorAction SilentlyContinue
        LogWrite "Storjshare Script Version Environment Variable Added: $script_ver"
    }
}

function autoupdate($howoften) {

    if(!($global:update)) {

        Copy-Item "${automated_script_path}automate_storj_cli.ps1" "$global:npm_path" -force -ErrorAction SilentlyContinue
        LogWrite "Script file copied to $global:npm_path"

        if(!($global:noautoupdate)) {
            $Arguments="-NoProfile -NoLogo -Noninteractive -WindowStyle Hidden -ExecutionPolicy Bypass ""${global:npm_path}automate_storj_cli.ps1"" -silent -update"
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $Arguments
            $trigger =  New-ScheduledTaskTrigger -Daily -At $global:checktime
            #can use -Credential as needed

            #if($global:runas) {
            #     Register-ScheduledTask -Action $action -User $global:username -Password "$global:password" -Trigger $trigger -TaskName "storjshare Auto-Update" -Description "Updates storjshare software $howoften at $global:checktime local time" -RunLevel Highest
            #} else {
                 Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "storjshare Auto-Update" -Description "Updates storjshare software $howoften at $global:checktime local time" -RunLevel Highest
            #}

            LogWrite "Scheduled Task Created"
        } else {
            LogWrite "No autoupdate specified skipping"
        }
    } else {
        LogWrite "Skipping autoupdate, update method on..."
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

handleParameters

LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Performing storjshare-cli Automated Management"
LogWrite -color Cyan "Script Version: $global:script_version"
LogWrite -color Cyan "Github Site: https://github.com/Storj/storj-automation"
LogWrite -color Red "USE AT YOUR OWN RISK"
LogWrite ""
LogWrite -color Yellow "Recommended Versions of Software"
LogWrite -color Cyan "Git for Windows: $gitforwindows_ver"
LogWrite -color Cyan "Node.js: $nodejs_ver"
LogWrite -color Cyan "Python: $python_ver"
LogWrite -color Cyan "Visual Studio: $visualstudio_ver Commmunity Edition"
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Checking for Pre-Requirements..."
LogWrite ""
LogWrite ""
LogWrite -color Yellow "Reviewing Git for Windows..."
GitForWindowsCheck $gitforwindows_ver
LogWrite -color Green "Git for Windows Review Completed"
LogWrite ""
LogWrite -color Yellow "Reviewing Node.js..."
NodejsCheck $nodejs_ver
LogWrite -color Green "Node.js Review Completed"
LogWrite ""
LogWrite -color Yellow "Reviewing Python..."
PythonCheck $python_ver
LogWrite -color Green "Python Review Completed"
LogWrite ""
LogWrite -color Yellow "Reviewing Visual Studio $visualstudio_ver Edition..."
VisualStudioCheck $visualstudio_ver $visualstudio_dl
LogWrite -color Green "Visual Studio $visualstudio_ver Edition Review Completed"
LogWrite ""
LogWrite ""
LogWrite -color Cyan "Completed Pre-Requirements Check"
LogWrite ""
LogWrite -color Yellow "=============================================="
checkRebootNeeded
LogWrite ""
LogWrite -color Cyan "Reviewing storjshare-cli..."
storjshare-cliCheck
LogWrite -color Green "storjshare-cli Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing UPNP..."
CheckUPNP
LogWrite -color Green "UPNP Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing storjshare Automated Setup..."
setup-storjshare
LogWrite -color Green "storjshare Automated Setup Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Service..."
nssmCheck $nssm_ver
LogWrite -color Green "Service Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Script Registry Version..."
storjshare_cli_checkver $global:script_version
LogWrite -color Green "Script Registry Version Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Auto-Update Ability..."
autoupdate $global:howoften
LogWrite -color Green "Auto-Update AbilityReview Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Completed storjshare-cli Automated Management"
LogWrite -color Cyan "storjshare-cli should now be running as a windows service."
LogWrite -color Cyan "You can check Control Panel > Administrative Tools -> Services -> storjshare-cli and see if the service is running"
LogWrite -color Cyan "You can also check %WINDIR%\Temp\storj\cli to see if any logs are generating and what the details of the logs are saying"
LogWrite -color Cyan "$global:datadir\farms.db folder should slowly start building up shards (ldb files) if everything is configured properly"
LogWrite ""
LogWrite -color Yellow "=============================================="
ErrorOut -code $global:return_code
