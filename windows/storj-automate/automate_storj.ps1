#Requires -Version 3
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Automates the management of storj for Windows only
.DESCRIPTION
  Automates the management of storj for Windows only

  This checks for pre-req software
  Then it checks for storj
  Then it installs/updates storj

.INPUTS

.OUTPUTS
  Return Codes (follows .msi standards) (https://msdn.microsoft.com/en-us/library/windows/desktop/aa376931(v=vs.85).aspx)
#>

#-----------------------------------------------------------[Parameters]------------------------------------------------------------

param(
    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:script_version="1.3" # Script version
$global:return_code=$global:error_success #default success
$global:user_profile=$env:userprofile + '\' # (Default: %USERPROFILE%) - runas overwrites this variable
$global:appdata=$env:appdata + '\' # (Default: %APPDATA%\) - runas overwrites this variable
$global:npm_path='' + $global:appdata + "npm\"
$global:datadir=$global:user_profile + ".storj\" #Default: %USERPROFILE%\.storj
$global:storj_bin='' + $global:npm_path + "storj.cmd" # Default: storj-bridge location %APPDATA%\npm\storj-bridge.cmd" - runas overwrites this variable

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$windows_env=$env:windir
$work_directory='' + $windows_env + '\Temp\storj'
$save_dir=$work_directory + '\installs'
$storj_install_log_path=$save_dir
$storj_install_log_file=$storj_install_log_path + '\automate_storj.log'; #outputs everything to a file if -silent is used, instead of the console
$storj_log_path=$work_directory + '\core'

$nodejs_ver="4" #make sure to reference Major Branch Version (Default: 4)

$python_ver="2" #make sure to reference Major Branch Version (Default: 2)
$python_path = "C:\Python27\" #make sure ends with \ (Default: C:\Python27\)

$visualstudio_ver="2015" # currently only supports 2015 Edition (Default: 2015)
$visualstudio_dl="http://go.microsoft.com/fwlink/?LinkID=626924"  #  link to 2015 download   (Default: http://go.microsoft.com/fwlink/?LinkID=626924)

#Handles EXE Security Warnings
$Lowriskregpath ="HKCU:\Software\Microsoft\Windows\Currentversion\Policies\Associations"
$Lowriskregfile = "LowRiskFileTypes"
$LowRiskFileTypes = ".exe"

$error_success=0  #this is success
$error_invalid_parameter=87 #this is failiure, invalid parameters referenced
$error_install_failure=1603 #this is failure, A fatal error occured during installation (default error)
$error_success_reboot_required=3010  #this is success, but requests for reboot

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function handleParameters() {

    if(!(Test-Path -pathType container $storj_install_log_path)) {
        New-Item $storj_install_log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $storj_install_log_path)) {
		ErrorOut "Log Directory $storj_install_log_path failed to create, try it manually..."
	}

    if(!(Test-Path -pathType container $storj_log_path)) {
        New-Item $storj_log_path -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $storj_log_path)) {
		ErrorOut "Log Directory $storj_log_path failed to create, try it manually..."
	}

    if(!(Test-Path -pathType container $save_dir)) {
        New-Item $save_dir -type directory -force | Out-Null
    }

    if(!(Test-Path -pathType container $save_dir)) {
		ErrorOut "Save Directory $save_dir failed to create, try it manually..."
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
            if(!(Test-Path -pathType container $storj_install_log_path)) {

                New-Item $storj_install_log_path -type directory -force | Out-Null

                if(!(Test-Path -pathType container $storj_install_log_path)) {
		            ErrorOut "Log Directory $storj_install_log_path failed to create, try it manually..."
	            }
	        }
            Add-content $storj_install_log_file -value $logmessage
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

function GitForWindowsCheck() {
    LogWrite "Checking if Git for Windows is installed..."
    If(!(Get-IsProgramInstalled "Git")) {
        $url = "https://github.com/git-for-windows/git/releases/latest"
        $request = [System.Net.WebRequest]::Create($url)
        $request.AllowAutoRedirect=$false
        $response = $request.GetResponse()
 
        if ($response.StatusCode -eq "Found") {
            $url = $response.GetResponseHeader("Location")
        } else {
            ErrorOut "Unable to determine latest version for Git for Windows"
        }

        $version = $url.Substring(0,$url.Length-".windows.1".Length)
        $pos = $version.IndexOf("v")
        $version = $version.Substring($pos+1)

        LogWrite "Found Latest Version of Git for Windows - ${version}"

        LogWrite "Git for Windows is not installed."
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

        $url = "https://github.com/git-for-windows/git/releases/latest"
        $request = [System.Net.WebRequest]::Create($url)
        $request.AllowAutoRedirect=$false
        $response = $request.GetResponse()
 
        if ($response.StatusCode -eq "Found") {
            $url = $response.GetResponseHeader("Location")
        } else {
            ErrorOut "Unable to determine latest version for Git for Windows"
        }

        $version = $url.Substring(0,$url.Length-".windows.1".Length)
        $pos = $version.IndexOf("v")
        $version = $version.Substring($pos+1)

        LogWrite "Found Latest Version of Git for Windows - ${version}"

        $result = CompareVersions $installed_version $version
        if($result -eq "-2") {
            ErrorOut "Unable to match Git for Windows version (Installed Version: $installed_version / Requested Version: $version)"
        }

        if($result -eq 0)
        {
            LogWrite "Git for Windows is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Git for Windows is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Git for Windows is out of date."
            
            LogWrite -Color Cyan "Git for Windows $installed_version will be updated to $version..."
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
                ErrorOut "Git for Windows did not complete installation successfully...try manually updating it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Git for Windows Updated Successfully"
            $installed_version = $version           
        }

        LogWrite -color Green "Git for Windows Installed Version: $installed_version"
    }
}

function NodejsCheck([string]$version) {
    LogWrite "Checking if Node.js is installed..."
    If(!(Get-IsProgramInstalled "Node.js")) {
        LogWrite "Node.js is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='-x86'
        } else {
            $arch="64-bit"
            $arch_ver='-x64'
        }

        LogWrite "Gathering Latest Node.js for Major Version ${version}..."

        $url = "https://nodejs.org/dist/latest-v${version}.x/"
        $site = Invoke-WebRequest -URI "$url" -UseBasicParsing
        
        $found=0
        $site.Links | Foreach {
            $url_items = $_.href

            if($url_items -like "*${arch_ver}.msi") {
                $filename=$url_items
                $found=1
            }
        }

        if($found -ne 1) {
            ErrorOut "Unable to gather Node.js Version";
        }

        $url="${url}$filename"
        $version = $filename.Substring(0,$filename.Length-"${arch_ver}.msi".Length)
        $pos = $version.IndexOf("v")
        $version = $version.Substring($pos+1)
        LogWrite "Found Latest Version of Node.js - ${version}"

	    $save_path = '' + $save_dir + '\' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    ErrorOut "Save directory $save_dir does not exist";
	    }

        LogWrite "Downloading Node.js ($arch) $version..."
        DownloadFile $url $save_path
        LogWrite "Node.js downloaded"

	    LogWrite "Installing Node.js $version..."
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

        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver='-x86'
        } else {
            $arch="64-bit"
            $arch_ver='-x64'
        }

        LogWrite "Gathering Latest Node.js for Major Version ${version}..."
        $url = "https://nodejs.org/dist/latest-v${version}.x/"
        $site = Invoke-WebRequest -URI "$url" -UseBasicParsing
        
        $found=0
        $site.Links | Foreach {
            $url_items = $_.href

            if($url_items -like "*${arch_ver}.msi") {
                $filename=$url_items
                $found=1
            }
        }

        if($found -ne 1) {
            ErrorOut "Unable to gather Node.js Version";
        }

        $url="${url}$filename"
        $version = $filename.Substring(0,$filename.Length-"${arch_ver}.msi".Length)
        $pos = $version.IndexOf("v")
        $version = $version.Substring($pos+1)
        LogWrite "Found Latest Version ${version}"

        $result = CompareVersions $installed_version $version
        if($result -eq "-2") {
            ErrorOut "Unable to match Node.js version (Installed Version: $installed_version / Requested Version: $version)"
        }

        if($result -eq 0)
        {
            LogWrite "Node.js is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Node.js is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Node.js is out of date."
            LogWrite -Color Cyan "Node.js $installed_version will be updated to $version..."

	        $save_path = '' + $save_dir + '\' + $filename;

	        if(!(Test-Path -pathType container $save_dir)) {
		        ErrorOut "Save directory $save_dir does not exist";
	        }

            LogWrite "Downloading Node.js ($arch) $version..."
            DownloadFile $url $save_path
            LogWrite "Nodejs downloaded"

	        LogWrite "Installing Node.js $version..."
	        InstallMSI $save_path
        
            If(!(Get-IsProgramInstalled "Node.js")) {
               ErrorOut "Node.js did not complete installation successfully...try manually updating it..."
            }

            $global:reboot_needed="true"
            LogWrite -color Green "Node.js Updated Successfully"
            $installed_version = $version
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
        LogWrite "Python is not installed."
        if ([System.IntPtr]::Size -eq 4) {
            $arch="32-bit"
            $arch_ver=''
        } else {
            $arch="64-bit"
            $arch_ver='.amd64'
        }

        $url = "https://www.python.org/ftp/python/"
        $site = Invoke-WebRequest -URI "$url" -UseBasicParsing
        
        $last=-1
        $site.Links | Foreach {
            $url_items = $_.href
            if($url_items -like "${version}.*") {
                $filename=$url_items
                $filename=$filename.Substring(0,$filename.Length-1)
                $version_check=$filename.Substring($version.Length+1)
                
                if($version_check.IndexOf(".") -gt 0) {
                    $pos = $version_check.IndexOf(".")
                    $get_version_part=$version_check.Substring(0,$pos)
                } else {
                     $get_version_part=$version_check
                }

                if([int]$get_version_part -gt [int]$last) {
                    $last=$get_version_part
                }
                
            }
        }

        $version="${version}.${last}"
        $last=-1
        $site.Links | Foreach {
            $url_items = $_.href
            if($url_items -like "${version}.*") {
                $filename=$url_items
                $filename=$filename.Substring(0,$filename.Length-1)
                $version_check=$filename.Substring($version.Length+1)
                
                if($version_check.IndexOf(".") -gt 0) {
                    $pos = $version_check.IndexOf(".")
                    $get_version_part=$version_check.Substring(0,$pos)
                } else {
                     $get_version_part=$version_check
                }

                if([int]$get_version_part -gt [int]$last) {
                    $last=$get_version_part
                }
                
            }
        }
        $version="${version}.${last}"

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

        $url = "https://www.python.org/ftp/python/"
        $site = Invoke-WebRequest -URI "$url" -UseBasicParsing
        
        $last=-1
        $site.Links | Foreach {
            $url_items = $_.href
            if($url_items -like "${version}.*") {
                $filename=$url_items
                $filename=$filename.Substring(0,$filename.Length-1)
                $version_check=$filename.Substring($version.Length+1)
                
                if($version_check.IndexOf(".") -gt 0) {
                    $pos = $version_check.IndexOf(".")
                    $get_version_part=$version_check.Substring(0,$pos)
                } else {
                     $get_version_part=$version_check
                }

                if([int]$get_version_part -gt [int]$last) {
                    $last=$get_version_part
                }
                
            }
        }

        $version="${version}.${last}"
        $last=-1
        $site.Links | Foreach {
            $url_items = $_.href
            if($url_items -like "${version}.*") {
                $filename=$url_items
                $filename=$filename.Substring(0,$filename.Length-1)
                $version_check=$filename.Substring($version.Length+1)
                
                if($version_check.IndexOf(".") -gt 0) {
                    $pos = $version_check.IndexOf(".")
                    $get_version_part=$version_check.Substring(0,$pos)
                } else {
                     $get_version_part=$version_check
                }

                if([int]$get_version_part -gt [int]$last) {
                    $last=$get_version_part
                }
                
            }
        }
        $version="${version}.${last}"

        $result = CompareVersions $installed_version $version
        if($result -eq "-2") {
            ErrorOut "Unable to match Python version (Installed Version: $installed_version / Requested Version: $version)"
        }

        if($result -eq 0)
        {
            LogWrite "Python is already updated. Skipping..."
        } elseif($result -eq 1) {
            LogWrite "Python is newer than the recommended version. Skipping..."
        } else {
            LogWrite "Python is out of date."
            LogWrite -Color Cyan "Python $installed_version will be updated to $version..."
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
            LogWrite -color Green "Python Updated Successfully"
            $installed_version=$version
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

function storjCheck() {
    LogWrite "Checking if storj is installed..."
    $Arguments = "list -g"
    $output=(UseNPM $Arguments| Where-Object {$_ -like '*storj*'})

    #write npm logs to log file if in silent mode
    if($silent) {
        LogWrite "npm $Arguments results"
        Add-content $storj_install_log_file -value $output
    }

    if (!$output.Length -gt 0) {
        LogWrite "storj is not installed."
        LogWrite "Installing storj (latest version released)..."

        $Arguments = "install -g storj"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $storj_install_log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storj did not complete installation successfully...try manually installing it..."
        }

        LogWrite -color Green "storj Installed Successfully"
    }
    else
    {
        LogWrite "storj already installed."

        if(Test-Path $storj_log_path) {
            LogWrite "Removing Logs files $storj_log_path"
            Remove-Item "$storj_log_path\*" -force
        }

        LogWrite -color Cyan "Performing storj Update..."

        #$Arguments = "update -g storj"
        $Arguments = "install -g storj"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $storj_install_log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storj did not complete update successfully...try manually updating it..."
        }
        
        LogWrite -color Green "storj Update Completed"

        LogWrite -color Cyan "Checking storj version..."

        $pos=$output.IndexOf("storj")

        $version = $output.Substring($pos+6)

        if(!$version) {
            ErrorOut "storj Version is Unknown - Error"
        }

        LogWrite -color Green "storj Installed Version: $version"
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
	$save_path = '' + $storj_install_log_path + '\' + $filename;

	$filename_err = 'npm_output_err.log';
	$save_path_err = '' + $storj_install_log_path + '\' + $filename_err;
	if(!(Test-Path -pathType container $storj_install_log_path)) {
	    ErrorOut "Log directory $storj_install_log_path does not exist";
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

#-----------------------------------------------------------[Execution]------------------------------------------------------------

handleParameters

LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Performing storj Automated Management"
LogWrite -color Cyan "Script Version: $global:script_version"
LogWrite -color Cyan "Github Site: https://github.com/Storj/storj-automation"
LogWrite -color Red "USE AT YOUR OWN RISK"
LogWrite ""
LogWrite -color Yellow "Recommended Versions of Software"
LogWrite -color Cyan "Git for Windows: Latest Version"
LogWrite -color Cyan "Node.js - Major Branch: $nodejs_ver"
LogWrite -color Cyan "Python - Major Branch: $python_ver"
LogWrite -color Cyan "Visual Studio: $visualstudio_ver Commmunity Edition"
LogWrite -color Yellow "=============================================="
LogWrite ""
LogWrite -color Cyan "Checking for Pre-Requirements..."
LogWrite ""
LogWrite ""
LogWrite -color Yellow "Reviewing Git for Windows..."
GitForWindowsCheck
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
LogWrite -color Cyan "Reviewing storj..."
storjCheck
LogWrite -color Green "storj Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Completed storj Automated Management"
LogWrite -color Cyan "You can now utilize Storj core"
LogWrite ""
LogWrite -color Yellow "=============================================="
ErrorOut -code $global:return_code
