#Requires -Version 2
#Requires –RunAsAdministrator
<#
.SYNOPSIS
  Automates the installation of storjshare-cli for Windows only
.DESCRIPTION
  Automates the installation of storjshare-cli for Windows only
  
  Ensure Set-ExecutionPolicy Unrestricted is set before running this
  Ensure the script is Run as Administrator

  To run double-click

  Functions this performs
    --Checks for Python version 2.7.11 and installs if it is not installed
    --Checks for PATH Envrionment variable for Python and creates it if it does not exist
.NOTES
  Version:        0.1
  Author:         Storj Community
  Creation Date:  06/03/2016

#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$client = New-Object System.Net.WebClient

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$save_dir=Resolve-Path ~/Downloads
$python_ver="2.7.11"
$python_path = "C:\Python27\"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function InstallMSI($installer) {
	$Arguments = @()
	$Arguments += "/i"
	$Arguments += "`"$installer`""
	$Arguments += "ALLUSERS=`"1`""
	$Arguments += "/passive"

	Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
}

function download_file([string]$url, [string]$d) {
	if(!(Test-Path $d -pathType leaf)) {
		# get the file
		write-host "Downloading $url to $d";
		$client.DownloadFile($url, $d);

        if(!(Test-Path $d -pathType leaf)) {
		    write-host "Download failed for $url"
            exit;
	    }
	}
    else
    {
        write-host "Download file" $d "already exists";
    }
}

function get-python-ver($version) {

    If(!(Is-Installed "Python")) {

        if ([System.IntPtr]::Size -eq 4) {
            write-host "32-bit OS detected"
            write-host "Installing 32-bit Python"
            $arch_ver=''
        }
        else {
            write-host "64-bit OS detected"
            write-host "Installing 64-bit Python"
            $arch_ver='.amd64'
        }

	    $filename = 'python-' + $version + $arch_ver + '.msi';
	    $save_path = '' + $save_dir + '\' + $filename;
	    if(!(Test-Path -pathType container $save_dir)) {
		    write-host -fore red $save_dir " does not exist";
		    exit;
	    }

	    $url='http://www.python.org/ftp/python/' + $version + '/' + $filename;
	
        write-host $url
        download_file $url $save_path
	    write-host "Installing Python"
	    InstallMSI $save_path $target_dir
    }
    else
    {
        write-host "Skipping install...Python already installed."
    }

    $PathasArray=($Env:PATH).split(';')
    If ($PathasArray -contains $python_path -or $PathAsArray -contains $python_path+'\') {
        write-host $python_path 'already within $ENV:PATH'
    }
    else
    {
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path 
        
        write-host $python_path[-1]

        $NewPath=$OldPath+';’+$python_path+';'+$python_path+"Scripts\"
        write-host $NewPath
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH –Value $newPath 
    }
}

function get_setuptools {
	write-host "Installing setuptools"
	$setuptools_url = "https://bitbucket.org/pypa/setuptools/raw/bootstrap/ez_setup.py"
	$ez_setup = '' + $save_dir + "\ez_setup.py"
	download_file $setuptools_url $ez_setup
	python $ez_setup
}

Function global:TEST-LocalAdmin() { 
    Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] "Administrator") 
}

function Is-Installed( $program ) {
    
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    return $x86 -or $x64;
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

get-python-ver $python_ver
