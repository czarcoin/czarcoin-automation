#Requires -Version 3
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Automates the management of storj-bridge for Windows only
.DESCRIPTION
  Automates the management of storj-bridge for Windows only

  This checks for pre-req software
  Then it checks for storj-bridge
  Then it updates storj-bridge

  Examples:
  To deploy silently use the following command
  ./automate_storj_bridge.ps1 -silent

  To enable UPNP
  ./automate_storj_bridge.ps1 -enableupnp

  To prevent the storj-bridge from being installed as a service
  ./automate_storj_bridge.ps1 -nosvc

  To remove service use the following command
  ./automate_storj_bridge.ps1 -removesvc

  To run as a service account in silent mode
  ./automate_storj_bridge.ps1 -silent -runas -username username -password password

.INPUTS
  -silent - [optional] this will write everything to a log file and prevent the script from running pause commands.
  -autoreboot - [optional] call autoreboot if you want this to autoreboot
  -enableupnp - [optional] Enables UPNP
  -nosvc - [optional] Prevents storj-bridge from being installed as a service
  -svcname [name] - [optional] Uses this name as the service to install or remove - storj-bridge is default
  -removesvc - [optional] Removes storjshare as a service (see the config section in the script to customize)
  -runas - [optional] Runs the script as a service account
    -username username [required] Username of the account
    -password 'password' [required] Password of the account
   -update - [optional] Performs an update only function and skips the rest

.OUTPUTS
  Return Codes (follows .msi standards) (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)

#>

#-----------------------------------------------------------[Parameters]------------------------------------------------------------

param(
    [Parameter(Mandatory=$false)]
    [SWITCH]$silent,

    [Parameter(Mandatory=$false)]
    [SWITCH]$autoreboot,

    [Parameter(Mandatory=$false)]
    [SWITCH]$enableupnp,

    [Parameter(Mandatory=$false)]
    [SWITCH]$nosvc,

    [Parameter(Mandatory=$false)]
    [SWITCH]$removesvc,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$svcname,

    [Parameter(Mandatory=$false)]
    [SWITCH]$runas,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$username,

    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
    [STRING]$password,

    [Parameter(Mandatory=$false)]
    [SWITCH]$update,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:script_version="3.0 Release" # Script version
$global:reboot_needed=""
$global:enableupnp=""
$global:autoreoot=""
$global:nosvc=""
$global:svcname=""
$global:runas=""
$global:username=""
$global:password=""
$global:noautoupdate=""
$global:howoften="Daily"
$global:checktime="3am"
$global:update=""
$global:return_code=$error_success #default success
$global:user_profile=$env:userprofile + '\' # (Default: %USERPROFILE%) - runas overwrites this variable
$global:appdata=$env:appdata + '\' # (Default: %APPDATA%\) - runas overwrites this variable
$global:mongodb_dbpath='' + $global:user_profile + '.storj-bridge\mongodb'; #Default %USERPROFILE%\.storj-bridge\ - runas overwrites this variable
$global:npm_path='' + $global:appdata + "npm\"
$global:storj_bridge_bin='' + $global:npm_path + "storj-bridge.cmd" # Default: storj-bridge location %APPDATA%\npm\storj-bridge.cmd" - runas overwrites this variable
$global:storj_brige_wa=$global:npm_path + "node_modules\storj-bridge"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$environment="production" # change to development if non-production (changes the config file name)  Default: production
$windows_env=$env:windir
$save_dir='' + $windows_env + '\Temp\storj\installs' # (Default: %WINDIR%\Temp\storj\bridge)
$log_path='' + $windows_env + '\Temp\storj\bridge' # (Default: %WINDIR%\Temp\storj\bridge)
$log_file=$save_dir + '\' + 'automate_storj_bridge.log'; #outputs everything to a file if -silent is used, instead of the console

$mongodb_ver="3.2.7" # (Default: 3.2.7)
$mongodb_svc_name="MongoDB"
$mongod_path='' + $env:programfiles + '\MongoDB\Server\3.2\bin\' #Default %PROGRAMFILES%\MongoDB\Server\3.2\bin\
$mongod_exe='' + $mongod_path + 'mongod.exe'; #Default: \mongod.exe
$mongodb_log='' + $save_dir + '\' + 'mongodb.log'; #Default: runas overwrites this variable

$erlang_ver="19.0" # Default: 19.0
$erlang_compare_ver="19 (8.0)" # Default: 19 (8.0)

$rabbitmq_ver="3.6.3" # Default: 3.6.2

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

$stor_bridge_svcname="storj-bridge"
$storj_bridge_log="$log_path\$stor_bridge_svcname.log"

$error_success=0  #this is success
$error_invalid_parameter=87 #this is failiure, invalid parameters referenced
$error_install_failure=1603 #this is failure, A fatal error occured during installation (default error)
$error_success_reboot_required=3010  #this is success, but requests for reboot

$automatic_restart_timeout=10  #in seconds Default: 30

$automated_script_path=Split-Path -parent $PSCommandPath
$automated_script_path=$automated_script_path + '\'

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function handleParameters() {

    if(!(Test-Path -pathType container $log_path)) {
        New-Item $log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $log_path)) {
		ErrorOut "Log Directory $log_path failed to create, try it manually..."
	}

    if(!(Test-Path -pathType container $save_dir)) {
        New-Item $save_dir -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $save_dir)) {
		ErrorOut "Save Directory $save_dir failed to create, try it manually..."
	}

    if($silent) {
        LogWrite "Logging to file $log_file"
    }
    else
    {
        $message="Logging to console"
        LogWrite $message
    }

    if($autoreboot) {
        LogWrite "Will auto-reboot if needed"
        $global:autoreboot="true"
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

        $global:mongodb_dbpath='' + $global:user_profile + '.storj-bridge\mongodb'

        $global:npm_path='' + $global:appdata + "npm\"
        $global:storj_bridge_bin='' + $global:npm_path + "storj-bridge.cmd" # Default: storj-bridge location %APPDATA%\npm\storj-bridge.cmd" - runas overwrites this variable
        $global:storj_brige_wa=$global:npm_path + "node_modules\storj-bridge"

        LogWrite "Using Service Account: $global:username"
        LogWrite "Granting $global:username Logon As A Service Right"
        Grant-LogOnAsService $global:username
    }

    if($update) {
        $global:update="true"
        LogWrite "Performing Update Only Function"

    } else {

        if ($enableupnp) {
            $global:enableupnp="true"
        }

        if($nosvc) {
            $global:nosvc="true"
        }

        if(!($svcname)) {
            $global:svcname="$stor_bridge_svcname"
        } else {
            $global:svcname="$svcname"
        }

        if ($removesvc) {
            $global:removesvc="true"
        }
    }

    #checks for unknown/invalid parameters referenced
    if ($other_args) {
        ErrorOut -code $error_invalid_parameter "ERROR: Unknown arguments: $args"
    }
}

Function LogWrite([string]$logstring,[string]$color) {
    $LogTime = Get-Date -Format "MM-dd-yyyy hh:mm:ss"
    $logmessage="["+$LogTime+"] "+$logstring
    if($silent) {
        if($logstring) {
            if(!(Test-Path -pathType container $log_path)) {

                New-Item $log_path -type directory -force | Out-Null

                if(!(Test-Path -pathType container $log_path)) {
		            ErrorOut "Log Directory $log_path failed to create, try it manually..."
	            }
	        }
            Add-content $log_file -value $logmessage
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

function MongoDBCheck([string]$version) {
    LogWrite "Checking if MongoDB is installed..."
    If(!(Get-IsProgramInstalled "MongoDB")) {
        LogWrite "MongoDB $version is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='-i386'
        } else {
            $arch="64-bit"
            $arch_ver='-x86_64-2008plus'
        }

	    $filename = 'mongodb-win32' + $arch_ver + '-' + $version + '-signed.msi';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='http://downloads.mongodb.org/win32/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist"
	    }

        LogWrite "Downloading MongoDB ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "MongoDB downloaded"

	    LogWrite "Installing MongoDB $version..."
	    InstallMSI $save_path
        
        If(!(Get-IsProgramInstalled "MongoDB")) {
           ErrorOut "MongoDB did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "MongoDB Installed Successfully"
    }
    else
    {
        LogWrite "MongoDB is already installed."
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "MongoDB" )
        if(!$installed_version) {
            ErrorOut "MongoDB Version is Unknown - Error"
        }

        $result = CompareVersions $installed_version $mongodb_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match MongoDB version (Installed Version: $installed_version / Requested Version: $mongodb_ver)"
        }

        if($result -eq 0) {
            LogWrite "MongoDB is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "MongoDB is newer than the recommended version. Skipping..."
        } else {
            LogWrite "MongoDB is out of date."
            
            LogWrite -Color Cyan "MongoDB $installed_version will be updated to $mongodb_ver..."
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver='-i386'
            } else {
                $arch="64-bit"
                $arch_ver='-x86_64-2008plus'
            }

            $filename = 'mongodb-win32' + $arch_ver + '-' + $mongodb_ver + '-signed.msi';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='http://downloads.mongodb.org/win32/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist"
	        }

            LogWrite "Downloading MongoDB ($arch) $mongodb_ver..."
            DownloadFile $url $save_path
            LogWrite "MongoDB downloaded"

	        LogWrite "Installing MongoDB $version..."
	        InstallMSI $save_path
        
            If(!(Get-IsProgramInstalled "MongoDB")) {
                ErrorOut "MongoDB did not complete installation successfully...try manually updating it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "MongoDB Updated Successfully"
            $installed_version = $mongodb_ver           
        }

        LogWrite -color Green "MongoDB Installed Version: $installed_version"
    }

    if(!($global:update)) {

        LogWrite "Checking for MongoDB Service"

        if(CheckService($mongodb_svc_name)) {
            LogWrite "MongoDB Service Already Installed, skipping..."
        } else {
            LogWrite "Installing MongoDB Service"

            if(!(Test-Path -pathType container $global:mongodb_dbpath)) {
		        LogWrite "Database Directory $global:mongodb_dbpath does not exist, creating..."

                New-Item $global:mongodb_dbpath -type directory -force | Out-Null
            
                if(!(Test-Path -pathType container $global:mongodb_dbpath)) {
		            ErrorOut "Database Directory $global:mongodb_dbpath failed to create, try it manually..."
	            }
	        }

 	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Log Directory $save_dir does not exist"
	        }

            $Arguments="--install "
            $Arguments+="--dbpath $global:mongodb_dbpath "
            $Arguments+="--logpath $mongodb_log"

            if($silent) {
                Start-Process "`"$mongod_exe`"" -ArgumentList $Arguments -NoNewWindow -Wait
            } else {
                Start-Process "`"$mongod_exe`"" -ArgumentList $Arguments -Wait
            }

            if(CheckService($mongodb_svc_name)) {
                LogWrite -color Green "MongoDB Service Installed Successfully"
                $global:reboot_needed="true"
            } else {
                ErrorOut "MongoDB Service Failed to Install...try it manually..."
            }
        }

        if($global:runas) {
            ChangeLogonService -svc_name $mongodb_svc_name -username $global:username -password $global:password
        }

    } else {
        LogWrite "Skipping service functions, in update mode"
    }
}

function ErlangCheck([string]$version) {
    LogWrite "Checking if Erlang is installed..."
    If(!(Get-IsProgramInstalled "Erlang")) {
        LogWrite "Erlang $version is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='32_'
        } else {
            $arch="64-bit"
            $arch_ver='64_'
        }

	    $filename = 'otp_win' + $arch_ver + $version + '.exe';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='http://erlang.org/download/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist"
	    }

        LogWrite "Downloading Erlang ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "Erlang ($arch) $erlang_ver downloaded"

	    LogWrite "Installing Erlang ($arch) $version..."
        $Arguments = "/S"
	    InstallEXE $save_path $Arguments
        
        If(!(Get-IsProgramInstalled "Erlang")) {
           ErrorOut "Erlang did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "Erlang Installed Successfully"
    }
    else
    {
        LogWrite "Erlang is already installed. Skipping install..."

        <#  DOES NOT SUPPORT UPDATING (JUST YET)
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "Erlang" )
        if(!$installed_version) {
            ErrorOut "Erlang Version is Unknown - Error"
        }

        $result = CompareVersions $installed_version $erlang_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match Erlang version (Installed Version: $installed_version / Requested Version: $erlang_ver)"
        }

        if($result -eq 0)
        {
            LogWrite "Erlang is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Erlang is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Erlang is out of date."
            
            if ([System.IntPtr]::Size -eq 4) {
                $arch="32-bit"
                $arch_ver='32_'
            } else {
                $arch="64-bit"
                $arch_ver='64_'
            }

	        $filename = 'otp_win' + $arch_ver + $erlang_ver + '.exe';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='http://erlang.org/download/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist"
	        }

            LogWrite "Downloading Erlang ($arch) $erlang_ver..."
            DownloadFile $url $save_path
            LogWrite "Erlang ($arch) $erlang_ver downloaded"

	        LogWrite "Installing Erlang ($arch) $erlang_ver..."
            $Arguments = "/S"
	        InstallEXE $save_path $Arguments
        
            If(!(Get-IsProgramInstalled "Erlang")) {
               ErrorOut "Erlang did not complete installation successfully...try manually installing it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Erlang Updated Successfully"
            $installed_version = $erlang_ver
            
        }
        #>
    }
}

function RabbitMQCheck([string]$version) {
    LogWrite "Checking if RabbitMQ is installed..."
    If(!(Get-IsProgramInstalled "RabbitMQ")) {
        LogWrite "RabbitMQ $version is not installed."

	    $filename = 'rabbitmq-server-' + $version + '.exe';
	    $save_path = '' + $save_dir + '\' + $filename;
        $url='https://www.rabbitmq.com/releases/rabbitmq-server/v' + $version + '/' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist"
	    }

        LogWrite "Downloading RabbitMQ $version..."
        DownloadFile $url $save_path
        LogWrite "RabbitMQ downloaded"

	    LogWrite "InstallingRabbitMQ $version..."
        $Arguments = "/S"
	    InstallRabbitEXE $save_path $Arguments
        
        If(!(Get-IsProgramInstalled "RabbitMQ")) {
           ErrorOut "RabbitMQ did not complete installation successfully...try manually installing it..."
        }

        $global:reboot_needed="true"
        LogWrite -color Green "RabbitMQ Installed Successfully"
    }
    else
    {
        LogWrite "RabbitMQ is already installed."
        LogWrite "Checking version..."

        $installed_version = Get-ProgramVersion( "RabbitMQ" )
        if(!$installed_version) {
            ErrorOut "RabbitMQ Version is Unknown - Error"
        }

        $result = CompareVersions $installed_version $rabbitmq_ver
        if($result -eq "-2") {
            ErrorOut "Unable to match RabbitMQ version (Installed Version: $installed_version / Requested Version: $rabbitmq_ver)"
        }

        if($result -eq 0)
        {
            LogWrite "RabbitMQ is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "RabbitMQ is newer than the recommended version. Skipping..."
        } else {
            LogWrite "RabbitMQ is out of date."
            
            LogWrite -Color Cyan "Rabbit $installed_version will be updated to $rabbitmq_ver..."
	        
            $filename = 'rabbitmq-server-' + $rabbitmq_ver + '.exe';
	        $save_path = '' + $save_dir + '\' + $filename;
            $url='https://www.rabbitmq.com/releases/rabbitmq-server/v' + $rabbitmq_ver + '/' + $filename;
	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist"
	        }

            LogWrite "Downloading RabbitMQ $rabbitmq_ver..."
            DownloadFile $url $save_path
            LogWrite "RabbitMQ downloaded"

	        LogWrite "InstallingRabbitMQ $rabbitmq_ver..."
            $Arguments = "/S"
	        InstallEXE $save_path $Arguments
        
            If(!(Get-IsProgramInstalled "RabbitMQ")) {
               ErrorOut "RabbitMQ did not complete installation successfully...try manually installing it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "RabbitMQ Updated Successfully"
            $installed_version = $rabbitmq_ver            
        }
    }
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

function storj-bridgeCheck() {
    LogWrite "Checking if storj-bridge is installed..."
    $Arguments = "list -g"
    $output=(UseNPM $Arguments| Where-Object {$_ -like '*storj-bridge*'})

    #write npm logs to log file if in silent mode
    if($silent) {
        LogWrite "npm $Arguments results"
        Add-content $log_file -value $output
    }

    if (!$output.Length -gt 0) {
        LogWrite "storj-bridge is not installed."
        LogWrite "Installing storj-bridge (latest version released)..."

        $Arguments = "install -g storj-bridge"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storj-bridge did not complete installation successfully...try manually installing it..."
        }

        LogWrite -color Green "storj-bridge Installed Successfully"
    }
    else
    {
        LogWrite "storj-bridge already installed."

        LogWrite "Stopping $global:svcname service (if applicable)"

        Stop-Service $global:svcname -ErrorAction SilentlyContinue | Out-Null

        LogWrite -color Cyan "Performing storj-bridge Update..."

        #$Arguments = "update -g storj-bridge"
        $Arguments = "install -g storj-bridge"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storj-bridge did not complete update successfully...try manually updating it..."
        }
        
        LogWrite -color Green "storj-bridge Update Completed"

        LogWrite -color Cyan "Checking storj-bridge version..."

        $pos=$output.IndexOf("storj-bridge@")

        $version = $output.Substring($pos+15)
        if(!$version) {
            ErrorOut "storj-bridge Version is Unknown - Error"
        }

        Start-Service -Name $global:svcname -ErrorAction SilentlyContinue

        LogWrite -color Green "storj-bridge Installed Version: $version"
    }

    LogWrite "Checking for storj-bridge Environment Variable..."
    $env:NODE_ENV = [System.Environment]::GetEnvironmentVariable("NODE_ENV","Machine")
    If ($env:NODE_ENV) {
        LogWrite "storj-bridge Environment Variable (NODE_ENV - $env:NODE_ENV) is already set, skipping..."
    }
    else
    {
        [Environment]::SetEnvironmentVariable("NODE_ENV", $environment, "Machine")
        $env:NODE_ENV = [System.Environment]::GetEnvironmentVariable("NODE_ENV","Machine")
        LogWrite "storj-bridge Environment Variable Added: NODE_ENV - $env:NODE_ENV"
        $global:reboot_needed="true"
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

    if($silent) {
        Start-Process "`"$installer`"" -ArgumentList $Arguments -Wait -NoNewWindow
    } else {
        Start-Process "`"$installer`"" -ArgumentList $Arguments -Wait
    }
	RemoveLowRiskFiles
}

function InstallRabbitEXE([string]$installer, [string]$Arguments) {
	Unblock-File $installer
	AddLowRiskFiles

    if($silent) {
        Start-Process "`"$installer`"" -ArgumentList $Arguments -NoNewWindow
    } else {
        Start-Process "`"$installer`"" -ArgumentList $Arguments
    }

    Start-Sleep -s 20

	RemoveLowRiskFiles
}

function InstallMSI([string]$installer) {
	$Arguments = @()
	$Arguments += "/i"
	$Arguments += "`"$installer`""
	$Arguments += "ALLUSERS=`"1`""
	$Arguments += "/passive"
	$Arguments += "/norestart"

    if($silent) {
        Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow
    } else {
        Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
    }
}

function UseNPM([string]$Arguments) {
	$filename = 'npm_output.log';
	$save_path = '' + $save_dir + '\' + $filename;

	$filename_err = 'npm_output_err.log';
	$save_path_err = '' + $save_dir + '\' + $filename_err;
	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Log directory $save_dir does not exist";
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
        if($global:autoreboot) {
            LogWrite -color Red "=============================================="
            LogWrite -color Red "Initiating Auto-Reboot in $automatic_restart_timeout seconds"
            Restart-Computer -Wait $automatic_restart_timeout
            ErrorOut -code $error_success_reboot_required "~~~Automatically Rebooting in $automatic_restart_timeout seconds~~~"
        } else {
            LogWrite -color Red "=============================================="
            LogWrite -color Red "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"
            LogWrite -color White "After the reboot, re-launch this script to complete the installation"
            ErrorOut -code $error_success_reboot_required "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"
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
        LogWrite "Attempting Enabling UPNP Old Fashioned Way"
        $results=SetUPNP "Yes" "Old"

        if($results -eq 0)
        {
            ErrorOut "Enabling UPNP failed to execute...try manually enabling UPNP..."
        } else {
            LogWrite -color Green "UPNP has been successfully enabled"
        }
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
        LogWrite "Attempting Enabling UPNP Old Fashioned Way"
        $results=SetUPNP "No" "Old"

        if($results -eq 0)
        {
            ErrorOut "Enabling UPNP failed to execute...try manually enabling UPNP..."
        } else {
            LogWrite -color Green "UPNP has been successfully enabled"
        }
        ErrorOut "Disabling UPNP failed to execute...try manually disabling UPNP..."
    } else {
        LogWrite -color Green "UPNP has been successfully disabled"
    }
}

function SetUPNP([string]$upnp_set, [string]$Old) {
	$filename = 'upnp_output.log';
	$save_path = '' + $save_dir + '\' + $filename;

	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Log directory $save_dir does not exist";
	}
	
    if($Old) {
        if($upnp_set -eq "Yes") {
            $upnp_set_result="enable"
        } else {
            $upnp_set_result="disable"
        }

        $Arguments="firewall set service type=upnp mode=$upnp_set_result"
    } else {
        $Arguments="advfirewall firewall set rule group=`"Network Discovery`" new enable=$($upnp_set)"
    }

    if($silent) {
        $proc = Start-Process "netsh" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow
    } else {
        $proc = Start-Process "netsh" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait
    }

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
        if($global:enableupnp) {
            EnableUPNP
        } else {
            DisableUPNP
        }
    } else {
        LogWrite "Skipping UPNP checks, Update function flagged..."
    }
}

function CheckService([string]$svc_name) {
    LogWrite "Checking if $svc_name Service is installed..."
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
	$save_path = '' + $save_dir + '\' + $filename;
	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Save directory $save_dir does not exist";
	}
	
    if($silent) {
        $proc = Start-Process "nssm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow
    } else {
        $proc = Start-Process "nssm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait
    }

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

    if($global:removesvc) {
        RemoveService $global:svcname
    }

    if(!($global:update)) {
        if(!($global:nosvc)) {
            if(!(CheckService $global:svcname)) {
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
                     LogWrite -color Green "NSSM already installed, skipping"
                }

                LogWrite "Installing service $global:svcname"
                $Arguments="install $global:svcname $global:storj_bridge_bin >> $storj_bridge_log"
                $results=UseNSSM $Arguments
                if(CheckService($global:svcname)) {
                    LogWrite -color Green "Service $global:svcname Installed Successfully"
                } else {
                    ErrorOut "Failed to install service $global:svcname"
                }

                #WORKAROUND#
                LogWrite "Setting service $global:svcname default directory to: $global:storj_brige_wa"
                $Arguments="set $global:svcname AppDirectory $global:storj_brige_wa"
                $results=UseNSSM $Arguments
                #WORKAROUND#

                ModifyService "$global:svcname" "Automatic"
                LogWrite "Starting $global:svcname service..."
                Start-Service $global:svcname -ErrorAction SilentlyContinue
            } else {
                LogWrite "Service $global:svcname already installed, skipping"
                Start-Service $global:svcname -ErrorAction SilentlyContinue
            }

            if($global:runas) {
                ChangeLogonService -svc_name $global:svcname -username $global:username -password $global:password
            }
        } else {
            LogWrite -color Green "Skipping Service Check/Installation - No Service Parameter passed"
        }
    } else {
        LogWrite "Skipping service functions, in update mode"
        Remove-Item $storj_bridge_log
        Start-Service -Name $global:svcname -ErrorAction SilentlyContinue
    }
}

function GetUserEnvironment([string]$env_var) {
	$filename = 'user_env.log';
	$save_path = '' + $log_path + '\' + $filename;

	if(!(Test-Path -pathType container $log_path)) {
	    ErrorOut "Save directory $log_path does not exist";
	}

    $Arguments="/c ECHO $env_var"

    if($silent) {
        $proc = Start-Process "cmd.exe" -Credential $global:credential -Workingdirectory "$env:windir\System32" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait -NoNewWindow
    } else {
        $proc = Start-Process "cmd.exe" -Credential $global:credential -Workingdirectory "$env:windir\System32" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Wait
    }

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
    secedit /export /cfg "$log_path\tempexport.inf"
    $curSIDs = Select-String "$log_path\tempexport.inf" -Pattern "SeServiceLogonRight" 
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
        $tempinf = Get-Content "$log_path\tempexport.inf"
        $tempinf = $tempinf.Replace($Sids,$newSids)
        Add-Content -Path "$log_path\tempimport.inf" -Value $tempinf
        secedit /import /db "$log_path\secedit.sdb" /cfg "$log_path\tempimport.inf" 
        secedit /configure /db "$log_path\secedit.sdb"
 
        gpupdate /force 
    }else{
        LogWrite "No new sids, skipping..."
    }
    del "$log_path\tempimport.inf" -force -ErrorAction SilentlyContinue
    del "$log_path\secedit.sdb" -force -ErrorAction SilentlyContinue
    del "$log_path\tempexport.inf" -force
}

function storj_bridge_checkver([string]$script_ver) {
    LogWrite "Checking for Storj Script Version Environment Variable..."
    $env:STORJ_BRIDGE_SCRIPT_VER = [System.Environment]::GetEnvironmentVariable("STORJ_BRIDGE_SCRIPT_VER","Machine")
    if ($env:STORJ_BRIDGE_SCRIPT_VER -eq $script_ver) {
    	LogWrite "STORJ_BRIDGE_SCRIPT_VER Environment Variable $script_ver already matches, skipping..."
    } else {
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name STORJ_BRIDGE_SCRIPT_VER -Value $script_ver -ErrorAction SilentlyContinue
        LogWrite "Storj Script Version Environment Variable Added: $script_ver"
    }
}

function autoupdate($howoften) {

    if(!($global:update)) {

        Copy-Item "${automated_script_path}automate_storj_bridge.ps1" "$global:npm_path" -force -ErrorAction SilentlyContinue
        LogWrite "Script file copied to $global:npm_path"

        if(!($global:noautoupdate)) {
            $Arguments="-NoProfile -NoLogo -Noninteractive -WindowStyle Hidden -ExecutionPolicy Bypass ""${global:npm_path}automate_storj_bridge.ps1"" -silent -update"
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $Arguments
            $trigger =  New-ScheduledTaskTrigger -Daily -At $global:checktime

            Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "storjshare Auto-Update" -Description "Updates storjshare software $howoften at $global:checktime local time" -RunLevel Highest -ErrorAction SilentlyContinue
            
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
LogWrite -color Cyan "Performing storj-bridge Automated Management"
LogWrite -color Cyan "Script Version: $global:script_version"
LogWrite -color Cyan "Github Site: https://github.com/Storj/storj-automation"
LogWrite -color Red "USE AT YOUR OWN RISK"
LogWrite ""
LogWrite -color Yellow "Recommended Versions of Software"
LogWrite -color Cyan "MongoDB: $mongodb_ver"
LogWrite -color Cyan "Git for Windows: $gitforwindows_ver"
LogWrite -color Cyan "Node.js: $nodejs_ver"
LogWrite -color Cyan "Python: $python_ver"
LogWrite -color Cyan "Erlang: $erlang_ver"
LogWrite -color Cyan "RabbitMQ: $rabbitmq_ver"
LogWrite -color Cyan "Visual Studio: $visualstudio_ver Commmunity Edition"
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Checking for Pre-Requirements..."
LogWrite ""
LogWrite ""
LogWrite -color Yellow "Reviewing mongoDB..."
MongoDBCheck $mongodb_ver
LogWrite -color Green "mongoDB Review Completed"
LogWrite ""
LogWrite -color Yellow "Reviewing Erlang..."
ErlangCheck $erlang_ver
LogWrite -color Green "Erlang Review Completed"
LogWrite ""
LogWrite -color Yellow "Reviewing RabbitMQ..."
RabbitMQCheck $rabbitmq_ver
LogWrite -color Green "RabbitMQ Review Completed"
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
LogWrite -color Cyan "Reviewing storj-bridge..."
storj-bridgeCheck
LogWrite -color Green "storj-bridge Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing UPNP..."
CheckUPNP
LogWrite -color Green "UPNP Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Service..."
nssmCheck $nssm_ver
LogWrite -color Green "Service Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Script Registry Version..."
storj_bridge_checkver $global:script_version
LogWrite -color Green "Script Registry Version Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Reviewing Auto-Update Ability..."
autoupdate $global:howoften
LogWrite -color Green "Auto-Update AbilityReview Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "You may now follow the remaining setup instructions here (if applicable):"
LogWrite -color Cyan "https://github.com/Storj/bridge#manually"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Completed storj-bridge Automated Management"
LogWrite -color Yellow "=============================================="
ErrorOut -code $global:return_code
