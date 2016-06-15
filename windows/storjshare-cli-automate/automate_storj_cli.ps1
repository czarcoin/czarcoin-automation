#Requires -Version 5
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Automates the management of storjshare-cli for Windows only
.DESCRIPTION
  Automates the management of storjshare-cli for Windows only

  This checks for pre-req software
  Then it checks for storjshare-cli
  Then it updates storjshare-cli

  To deploy silently use the following command
  PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass ""automate_storj_cli.ps1"" -silent' -Verb RunAs}"
.INPUTS
  -silent - [optional] this will write everything to a log file and prevent the script from running pause commands.
  -noupnp - [optional] Disables UPNP
  -installsvc - [optional] Installs storjshare as a service (see the config section in the script to customize) -- VERY BETA
  -removesvc - [optional] Removes storjshare as a service (see the config section in the script to customize) -- VERY BETA
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

    [Parameter(Mandatory=$false)]
    [SWITCH]$removesvc,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:script_version="2.6 Release" # Script version
$global:reboot_needed=""
$global:noupnp=""
$global:installsvc=""
$global:error_success=0  #this is success
$global:error_invalid_parameter=87 #this is failiure, invalid parameters referenced
$global:error_install_failure=1603 #this is failure, A fatal error occured during installation (default error)
$global:error_success_reboot_required=3010  #this is success, but requests for reboot

$global:return_code=$global:error_success #default success

#----------------------------------------------------------[Declarations]----------------------------------------------------------


$save_dir=$env:temp #path for downloaded files (Default: %TEMP%)
$log_file='' + $save_dir + '\' + 'automate_storj_cli.log'; #outputs everything to a file if -silent is used, instead of the console

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
$nssm_location="$env:windir\System32" # Default windows directory
$nssm_bin='' + $nssm_location + '\' + "nssm.exe" # (Default: %WINDIR%\System32\nssm.exe)
$storjshare_bin='' + $env:appdata + '\' + "npm\storjshare.cmd" # Default: storjshare-cli location %APPDATA%\npm\storjshare.cmd"

$storjshare_svc_name="storjshare"
$storjshare_location="C:\storjshare"
$storjshare_password="1234"
$storjshare_log="$save_dir\storjshare_svc.log"
#-----------------------------------------------------------[Functions]------------------------------------------------------------

function handleParameters() {
    #checks the silent parameter and if true, writes to log instead of console, also ignores pausing
    if($silent) {
        LogWrite "Logging to file $log_file"
    }
    else
    {
        $message="Logging to console"
        LogWrite $message
    }

    #checks for noupnp flag
    if ($noupnp) {
        $global:noupnp="true"
    }

    #checks for installsvc flag
    if ($installsvc) {
        $global:installsvc="true"
    }

    #checks for installsvc flag
    if ($removesvc) {
        $global:removesvc="true"
    }

    #checks for unknown/invalid parameters referenced
    if ($other_args) {
        ErrorOut -code $global:error_invalid_parameter "ERROR: Unknown arguments: $args"
    }
}

Function LogWrite([string]$logstring,[string]$color) {
    $LogTime = Get-Date -Format "MM-dd-yyyy hh:mm:ss"
    $logmessage="["+$LogTime+"] "+$logstring
    if($silent) {
        if($logstring) {
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

function ErrorOut([string]$message,[int]$code=$global:error_install_failure) {
    LogWrite -color Red $message
    
    if($silent) {
    	LogWrite -color Red "Returning Error Code: $code"
    }
    
    WaitUser
    exit $code;
}

function WaitUser() {
    #pauses script to show results
    if(!$silent) {
        pause
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
    If ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        LogWrite "Python Environment Path $python_path already within System Environment Path, skipping..."
    }
    else
    {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue).Path
        $NewPath=$OldPath+';'+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue)
        LogWrite "Python Environment Path Added: $python_path"
        $global:reboot_needed="true"
    }

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    $python_path=$python_path+"Scripts\";
    If ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        LogWrite "Python Environment Path $python_path already within System Environment Path, skipping..."
    }
    else
    {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue)).Path
        $NewPath=$OldPath+';'+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue)
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
        Add-content $log_file -value $output
    }

    if (!$output.Length -gt 0) {
        LogWrite "storjshare-cli is not installed."
        LogWrite "Installing storjshare-cli (latest version released)..."

        $Arguments = "install -g storjshare-cli"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $log_file -value $result
        }

        if ($result.Length -gt 0) {
            ErrorOut "storjshare-cli did not complete installation successfully...try manually installing it..."
        }

        LogWrite -color Green "storjshare-cli Installed Successfully"
    }
    else
    {
        LogWrite "storjshare-cli already installed."

        LogWrite -color Cyan "Performing storjshare-cli Update..."

        $Arguments = "update -g storjshare-cli"
        $result=(UseNPM $Arguments| Where-Object {$_ -like '*ERR!*'})

        #write npm logs to log file if in silent mode
        if($silent) {
            LogWrite "npm $Arguments results"
            Add-content $log_file -value $result
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
	New-Item -Path $Lowriskregpath -Erroraction SilentlyContinue |out-null
	New-ItemProperty $Lowriskregpath -Name $Lowriskregfile -Value $LowRiskFileTypes -PropertyType String -ErrorAction SilentlyContinue |out-null
}

function RemoveLowRiskFiles() {
	Remove-ItemProperty -Path $Lowriskregpath -Name $Lowriskregfile -ErrorAction SilentlyContinue
}

function InstallEXE([string]$installer, [string]$Arguments) {
	Unblock-File $installer
	AddLowRiskFiles
	Start-Process "`"$installer`"" -ArgumentList $Arguments -Wait
	RemoveLowRiskFiles
}

function InstallMSI([string]$installer) {
	$Arguments = @()
	$Arguments += "/i"
	$Arguments += "`"$installer`""
	$Arguments += "ALLUSERS=`"1`""
	$Arguments += "/passive"
	$Arguments += "/norestart"

	Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
}

function UseNPM([string]$Arguments) {
	$filename = 'npm_output.log';
	$save_path = '' + $save_dir + '\' + $filename;
	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Save directory $save_dir does not exist";
	}
	
    $proc = Start-Process "npm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Passthru
    $proc.WaitForExit()

    if(!(Test-Path $save_path)) {
        ErrorOut "npm command $Arguments failed to execute...try manually running it..."
    }
    
    $results=(Get-Content -Path "$save_path")
    Remove-Item "$save_path"
    
    return $results
}

function CheckRebootNeeded() {
	if($global:reboot_needed) {
        LogWrite -color Red "=============================================="
        LogWrite -color Red "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"
        LogWrite -color White "After the reboot, re-launch this script to complete the installation"
        ErrorOut -code $global:error_success_reboot_required "~~~PLEASE REBOOT BEFORE PROCEEDING~~~"        
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
	$save_path = '' + $save_dir + '\' + $filename;
	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Save directory $save_dir does not exist";
	}
	
    $Arguments="advfirewall firewall set rule group=`"Network Discovery`" new enable=$($upnp_set)"
    $proc = Start-Process "netsh" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Passthru
    $proc.WaitForExit()

    if(!(Test-Path $save_path)) {
        ErrorOut "npm command $Arguments failed to execute...try manually running it..."
    }
    
    $results=(Get-Content -Path "$save_path") | Where-Object {$_ -like '*Ok*'}
    Remove-Item "$save_path"
    
    if($results.Length -eq 0) {
        return 0
    }

    return 1
}

function CheckUPNP() {
    LogWrite "Checking UPNP Flag..."
    if($global:noupnp) {
        DisableUPNP
    } else {
        EnableUPNP
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
        $serviceToRemove = Get-WmiObject -Class Win32_Service -Filter "name='$svc_name'"
        $serviceToRemove.delete()
        if(CheckService $svc_name -eq 1) {
            ErrorOut "Failed to remove $svc_name"
        } else {
            write-host "Service $svc_name successfully removed"
        }
    } else {
        write-host "Service $svc_name is not installed, skipping removal..."
    }
}

function UseNSSM([string]$Arguments) {
	$filename = 'nssm_output.log';
	$save_path = '' + $save_dir + '\' + $filename;
	if(!(Test-Path -pathType container $save_dir)) {
	    ErrorOut "Save directory $save_dir does not exist";
	}
	
    $proc = Start-Process "nssm" -ArgumentList $Arguments -RedirectStandardOutput "$save_path" -Passthru
    $proc.WaitForExit()

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
            Add-Type -assembly “system.io.compression.filesystem”
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

function nssmCheck([string]$version,[string]$svc_name) {
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

        LogWrite "Checking for $svc_name to see if it exists"
        RemoveService $svc_name
    
        if($global:installsvc) {
            LogWrite "Installing service $svc_name"
            $Arguments="install $svc_name $storjshare_bin start --datadir $storjshare_location --password $storjshare_password >> $storjshare_log"
            $results=UseNSSM $Arguments
            if(CheckService($svc_name)) {
                LogWrite -color Green "Service $svc_name Installed Successfully"
            } else {
                ErrorOut "Failed to install service $svc_name"
            }
        }
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
LogWrite -color Cyan "Reviewing Service..."
nssmCheck $nssm_ver $storjshare_svc_name
LogWrite -color Green "Service Review Completed"
LogWrite ""
LogWrite -color Yellow "=============================================="
LogWrite -color Cyan "Completed storjshare-cli Automated Management"
LogWrite -color Yellow "=============================================="

ErrorOut -code $global:return_code
