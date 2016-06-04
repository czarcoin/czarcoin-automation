#Requires -Version 2
#Requires –RunAsAdministrator
<#
.SYNOPSIS
  Automates the installation of storjshare-cli for Windows only
.DESCRIPTION
  Automates the installation of storjshare-cli for Windows only
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$client = New-Object System.Net.WebClient
$script_version = "0.3 Beta"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$save_dir=$env:temp #path for downloaded files (Default: %TEMP%)

$gitforwindows_ver="2.8.3"  #   (Default: 2.8.3)

$nodejs_ver="4.4.5" #make sure to reference LTS branch version (Default: 4.4.5)

$python_ver="2.7.11" #currently only use version 2 branch (Default: 2.7.11)
$python_path = "C:\Python27\" #make sure ends with \ (Default: C:\Python27\)

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function GitForWindowsCheck([string]$version) {
    write-host "Checking if Git for Windows is installed..."
    If(!(Get-IsProgramInstalled "Git")) {
        write-host "Git for Windows $version is not installed."
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
		    write-host -fore red "Save directory " $save_dir " does not exist";
		    exit;
	    }

        write-host "Downloading Git for Windows ("$arch")" $version "..."
        DownloadFile $url $save_path
        write-host "Git for Windows downloaded"

	    write-host "Installing Git for Windows $version..."
        $Arguments = "/SILENT"
        $Arguements += "/COMPONENTS=""icons,ext\reg\shellhere,assoc,assoc_sh"""
	    InstallEXE $save_path $Arguments
        
        If(!(Get-IsProgramInstalled "Git")) {
           write-host -fore red "Git for Windows did not complete installation successfully...try manually installing it..."
           exit;
        }

        write-host "Git for Windows Installed Successfully"
    }
    else
    {
        write-host "Git for Windows already installed."
        write-host "Checking version..."

        $version = Get-ProgramVersion( "Git" )
        if(!$version) {
            write-host -fore red "Git for Windows Version is Unknown - Error"
            exit;
        }

        write-host -fore Green "Git for Windows Installed Version:" $version
    }
}

function NodejsCheck([string]$version) {
    write-host "Checking if Node.js is installed..."
    If(!(Get-IsProgramInstalled "Node.js")) {
        write-host "Nodejs $version is not installed."
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
		    write-host -fore red "Save directory " $save_dir " does not exist";
		    exit;
	    }

        write-host "Downloading Node.js LTS ("$arch")" $version "..."
        DownloadFile $url $save_path
        write-host "Nodejs downloaded"

	    write-host "Installing Node.js LTS $version..."
	    InstallMSI $save_path
        
        If(!(Get-IsProgramInstalled "Node.js")) {
           write-host -fore red "Node.js did not complete installation successfully...try manually installing it..."
           exit;
        }

        write-host "Node.js Installed Successfully"
    }
    else
    {
        write-host "Node.js already installed."
        write-host "Checking version..."

        $version = Get-ProgramVersion( "Node.js" )
        if(!$version) {
            write-host -fore red "Node.js Version is Unknown - Error"
            exit;
        }

        write-host -fore Green "Node.js Installed Version:" $version
    }
}

function PythonCheck([string]$version) {
    write-host "Checking if Python is installed..."
    If(!(Get-IsProgramInstalled "Python")) {
        write-host "Python $version is not installed."
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
		    write-host -fore red "Save directory " $save_dir " does not exist";
		    exit;
	    }

        write-host "Downloading Python ("$arch")" $version "..."
        DownloadFile $url $save_path
        write-host "Python downloaded"

	    write-host "Installing Python $version..."
	    InstallMSI $save_path
        
        If(!(Get-IsProgramInstalled "Python")) {
           write-host -fore red "Python did not complete installation successfully...try manually installing it..."
           exit;
        }

        write-host "Python Installed Successfully"
    }
    else
    {
        write-host "Python already installed."
        write-host "Checking version..."

        $version = Get-ProgramVersion( "Python" )
        if(!$version) {
            write-host -fore red "Python Version is Unknown - Error"
            exit;
        }

        write-host -fore Green "Python Installed Version:" $version
        if($version.Split(".")[0] -gt "2" -Or $version.Split(".")[0] -lt "2") {
            write-host -fore red "Python version not supported.  Please remove all versions of Python and run the script again."
            exit;
        }
    }

    write-host "Checking for Python Environment Path..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    If ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        write-host "Python Environment Path" $python_path 'already within System Environment Path, skipping...'
    }
    else
    {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $NewPath=$OldPath+';’+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH –Value $newPath
        write-host "Python Environment Path Added:" $python_path
    }

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $PathasArray=($Env:PATH).split(';')
    $python_path=$python_path+"Scripts\";
    If ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        write-host "Python Environment Path" $python_path 'already within System Environment Path, skipping...'
    }
    else
    {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $NewPath=$OldPath+';’+$python_path;
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH –Value $newPath
        write-host "Python Environment Path" $python_path 'already within System Environment Path, skipping...'
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

function Get-IsProgramInstalled([string]$program) {
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    return $x86 -or $x64;
}

function Get-ProgramVersion([string]$program) {
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } |
        Select-Object { $_.GetValue( "DisplayVersion" ) }  )

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
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
	    write-host $targetFile "exists, using this download";
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

function InstallEXE([string]$installer, [string]$Arguments) {
	Start-Process "`"$installer`"" -ArgumentList $Arguments -Wait
}

function InstallMSI([string]$installer) {
	$Arguments = @()
	$Arguments += "/i"
	$Arguments += "`"$installer`""
	$Arguments += "ALLUSERS=`"1`""
	$Arguments += "/passive"

	Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

write-host -fore Cyan "Performing Storj-cli Automated Installation"
write-host -fore Cyan "Script Version:"$script_version
write-host -fore Cyan "Github Site: https://github.com/Storj/storj-automation"
write-host -fore Red "USE AT YOUR OWN RISK"
write-host ""
write-host -fore Cyan "Checking for Pre-Requirements..."
write-host ""
write-host ""
write-host -fore Yellow "Reviewing Git for Windows..."
GitForWindowsCheck $gitforwindows_ver
write-host -fore Green "Git for Windows Review Completed"
write-host ""
write-host ""
write-host -fore Yellow "Reviewing Node.js..."
NodejsCheck $nodejs_ver
write-host -fore Green "Node.js Review Completed"
write-host ""
write-host -fore Yellow "Reviewing Python..."
PythonCheck $python_ver
write-host -fore Green "Python Review Completed"
write-host ""
write-host ""
write-host -fore Cyan "Completed Storj-cli Automated Installion"

#pauses script to show results
pause
