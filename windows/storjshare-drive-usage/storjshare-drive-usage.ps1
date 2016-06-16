<#
.SYNOPSIS
  Generates a report on current storjshare drive usage
.DESCRIPTION
  Generates a report on current storjshare drive usage

  The declarations section can be modified to the location of each storjshare instance.
  Each location should end with a semi-colon (;).

  The smallest amount reported is KB and the largest is PB

  Example:
    $storjshareFolders = "E:\storjshare;"
    $storjshareFolders += "F:\storjshare;"

.OUTPUTS
  Report of each folder's usage and total usage.
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$global:total=0
$global:script_version="1.2 Release"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$storjshareFolders = "E:\;"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function ConvertSize($size) {
#Accepts $size in KB

    if($size -ge 1000) {
        $size=$size / 1000
        $unit="MB"
        if($size -ge 1000) {
            $size=$size / 1000
            $unit="GB"
            if($size -ge 1000) {
                $size=$size / 1000
                $unit="TB"
                if($size -ge 1000) {
                    $size=$size / 1000
                    $unit="PB"
                }
            }
        }
    } else {
        $unit="KB"
    }

    $size=[math]::Round($size,2)

    $results+="$size $unit"
    return $results
}

function GetFolderSize([string]$folder) {
    $results=""
    $colItems = (Get-ChildItem $folder -recurse | Where-Object {$_.PSIsContainer -eq $True} | Sort-Object)
    foreach ($i in $colItems) {
        $subFolderItems = (Get-ChildItem $i.FullName | Measure-Object -ErrorAction SilentlyContinue -property length -sum)
        $sum=$subFolderItems.sum / 1KB
        $global:total+=$sum

        $results=ConvertSize $sum

        $result=$i.FullName + " -- " + "{0:N2}" -f ($results)
        write-host "$result"
    }
}

function GetStorjshareList([string]$folders) {
    foreach ($i in $folders.Split(";")) {
        if($i) {
          GetFolderSize $i
        }
    }

    $global:total=ConvertSize $global:total
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

write-host -ForegroundColor Yellow "=============================================="
write-host -ForegroundColor Cyan "Generating storjshare-size Report"
write-host -ForegroundColor Cyan "Script Version: $global:script_version"
write-host -ForegroundColor Cyan "Github Site: https://github.com/Storj/storj-automation"
write-host -ForegroundColor Red "USE AT YOUR OWN RISK"
write-host -ForegroundColor Yellow "=============================================="
write-host ""
write-host -ForegroundColor Cyan "Checking Disk Space For Each Folder..."
write-host ""
GetStorjshareList $storjshareFolders
write-host ""
write-host -ForegroundColor Yellow "=============================================="
write-host -ForegroundColor Green "Total Disk Space Used: $global:total"
write-host ""
write-host -ForegroundColor Yellow "=============================================="
write-host -ForegroundColor Cyan "Completed storjshare-size Report"
write-host -ForegroundColor Yellow "=============================================="

pause
