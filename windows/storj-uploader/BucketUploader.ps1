param(
    [Parameter(Mandatory=$false)]
    [STRING]$command,

    [Parameter(Mandatory=$false)]
    [STRING]$bucket,

    [Parameter(Mandatory=$false)]
    [STRING]$file,

    [parameter(Mandatory=$false,ValueFromRemainingArguments=$true)]
    [STRING]$other_args
 )

$host.ui.RawUI.WindowTitle = 'Storj - Bucket Uploader';

$files = "C:\Windows\Temp\storj\bucket_uploader\uploads\"
$tmp="C:\Windows\Temp\storj\bucket_uploader\logs\"
$bucket=""
$password = ""
$b=0
$script="${PSScriptRoot}\BucketUploader.ps1"
$max_connections=4
$wordToFind = "File successfully stored"

    if(!(Test-Path -pathType container $files)) {
        New-Item $files -type directory -force | Out-Null
    }
    
        if(!(Test-Path -pathType container $tmp)) {
        New-Item $tmp -type directory -force | Out-Null
    }

function handleParameters() {

    if($command) {
        storj-command $command $bucket "${file}"
        exit
    }

    #checks for unknown/invalid parameters referenced
    if ($other_args) {
        write-host "ERROR: Unknown arguments: $other_args"
        exit
    }

    init
}

function storj-command($command, $bucket, $file) {

if ($command -eq "upload-file") {
        $arguments = "/c ""storj ${command} ${bucket} ""${file}"" -k ${password}"""
    } else {
        write-host "ERROR: Unknown storj command: $command"
        exit
    }

    $number=Get-Random

    Start-Process "cmd.exe" -ArgumentList $arguments -RedirectStandardOutput "${tmp}${number}.txt" -Wait -WindowStyle Minimized
    
    $file2 = Get-Content "${tmp}${number}.txt"
    $containsWord = $file2 | %{$_ -match $wordToFind}
    
    if($containsWord -contains $true) {
        Remove-Item "${tmp}${number}.txt"
    } else {
        Rename-Item "${tmp}${number}.txt" "${tmp}${number}_err.txt"
    }
    
    Remove-Item $file
}

function init() {
while($true){
$files = Get-ChildItem "${files}"
$connections=0
        
for ($i=0; $i -lt $files.Count; $i++) {

    if($connections -lt $max_connections) {

    $outfile = $files[$i].FullName

    Start-Process powershel1l -Argument "${script} upload-file ${bucket} ""${outfile}""" -WindowStyle Minimized

    $b=$b+1
} else {

    while($connections -ge $max_connections) {
        $connections = @(get-process -ea silentlycontinue powershel1l).count
         Write-Progress -Activity "Storj Uploader" -Status "Successful Uploads: $success / Failed Uploader: $failed" -CurrentOperation "Pending Available Resources...Connections: $connections"
    }
}
$connections = @(get-process -ea silentlycontinue powershel1l).count
$failed = Get-ChildItem -filter "*_err.txt" -path "${tmp}" | Measure-Object | Select -ExpandProperty Count
$success = $b - $failed
Write-Progress -Activity "Storj Uploader" -Status "Successful Uploads: $success / Failed Uploads: $failed" -CurrentOperation "Uploading to Bucket: $bucket"
}
}
}

handleParameters
