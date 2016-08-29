param(
    [Parameter(Mandatory=$false)]
    [STRING]$command,

    [Parameter(Mandatory=$false)]
    [STRING]$bucket,

    [Parameter(Mandatory=$false)]
    [STRING]$fileid,

    [Parameter(Mandatory=$false)]
    [STRING]$file,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

 $host.ui.RawUI.WindowTitle = 'Storj - Bucket Downloader';
  
$files = "C:\Windows\Temp\storj\bucket_downloader\downloads\"
$tmp="C:\Windows\Temp\storj\bucket_downloader\logs\"
$bucket="" # put your bucket ID here
$password="" # put your passphrase here
$b=0
$script="${PSScriptRoot}\BucketDownloader.ps1"
$max_connections=4
$wordToFind = "File downloaded and written"

    if(!(Test-Path -pathType container $files)) {
        New-Item $files -type directory -force | Out-Null
    }
    
        if(!(Test-Path -pathType container $tmp)) {
        New-Item $tmp -type directory -force | Out-Null
    }

function handleParameters() {

    if($command) {
        storj-command $command $bucket $fileid $file
        exit
    }

    #checks for unknown/invalid parameters referenced
    if ($other_args) {
        write-host "ERROR: Unknown arguments: $other_args"
        exit
    }

    init
}

function storj-command($command, $bucket, $fileid, $file) {

    if($command -eq "download-file") {
        $arguments = "/c ""storj ${command} ${bucket} ${fileid} ""${file}"" -k ${password}"""
    } else {
        write-host "ERROR: Unknown storj command: $command"
        exit
    }

    Start-Process "cmd.exe" -ArgumentList $arguments -RedirectStandardOutput "${tmp}${fileid}.txt" -Wait -WindowStyle Minimized
    
    $file = Get-Content "${tmp}${fileid}.txt"
    $containsWord = $file | %{$_ -match $wordToFind}

    if($containsWord -contains $true) {
        Remove-Item "${tmp}${fileid}.txt"
    } else {
        Rename-Item "${tmp}${fileid}.txt" "${tmp}${fileid}_err.txt"
    }

    Remove-Item $file
}

function init() {
while($true){
    $arguments = "/c ""storj list-files ${bucket}"""
    Start-Process "cmd.exe" -ArgumentList $arguments -RedirectStandardOutput "${tmp}list.txt" -Wait -WindowStyle Minimized
    
$lines=(Get-Content -Path "${tmp}list.txt")

$connections=0

foreach ($line in $lines) {
   
    if($connections -lt $max_connections) {
    
    $results= $line -split " "
    
    $fileid=$results[$results.Count-1]
    $outfile = $files + $fileid

    Start-Process powershel2l -Argument "${script} download-file ${bucket} ${fileid} ""${outfile}""" -WindowStyle Minimized
    
    $b=$b+1
} else {

    while($connections -ge $max_connections) {
        $connections = @(get-process -ea silentlycontinue powershel2l).count
        Write-Progress -Activity "Storj Downloader" -Status "Successful Downloads: $success / Failed Downloads: $failed" -CurrentOperation "Pending Available Resources...Connections: $connections"
    }
}
$connections = @(get-process -ea silentlycontinue powershel2l).count
$failed = Get-ChildItem -filter "*_err.txt" -path "${tmp}" | Measure-Object | Select -ExpandProperty Count
$success = $b - $failed
Write-Progress -Activity "Storj Downloader" -Status "Successful Downloads: $success / Failed Downloads: $failed" -CurrentOperation "Downloading Bucket: $bucket"
}

}
}

handleParameters
