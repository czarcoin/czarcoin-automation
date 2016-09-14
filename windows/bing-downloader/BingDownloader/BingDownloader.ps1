$i=0
$host.ui.RawUI.WindowTitle = 'Bing Downloader';

while($true){

# script parameters, feel free to change it 
$downloadFolder = "C:\Windows\Temp\storj\bucket_uploader\uploads"
$searchFor = Get-Random -InputObject (get-content C:\storj\scripts\wordsEn.txt) # place word file wherever or if you would like something else just update it with what you want
$nrOfImages = 9999

write-host "word selected: $searchFor"

# create a WebClient instance that will handle Network communications 
$webClient = New-Object System.Net.WebClient

# load System.Web so we can use HttpUtility
Add-Type -AssemblyName System.Web

# URL encode our search query
$searchQuery = [System.Web.HttpUtility]::UrlEncode($searchFor)

$nextpage=0

while($nextpage -lt $nrOfImages) {

$url = "http://www.bing.com/images/search?q=$searchQuery&first=$nextPage&count=$nrOfImages&qft=+filterui%3alicense-L2_L3_L4"

# get the HTML from resulting search response
$webpage = $webclient.DownloadString($url)

# use a 'fancy' regular expression to finds Urls terminating with '.jpg' or '.png'
$regex = "[(http(s)?):\/\/(www\.)?a-z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-z0-9@:%_\+.~#?&//=]*)((.jpg(\/)?)|(.png(\/)?)){1}(?!([\w\/]+))"

$listImgUrls = $webpage | Select-String -pattern $regex -Allmatches | ForEach-Object {$_.Matches} | Select-Object $_.Value -Unique

# let's figure out if the folder we will use to store the downloaded images already exists
if((Test-Path $downloadFolder) -eq $false) 
{

    New-Item -ItemType Directory -Path $downloadFolder | Out-Null
}


foreach($imgUrlString in $listImgUrls) 
{
    [Uri]$imgUri = New-Object System.Uri -ArgumentList $imgUrlString

    # this is a way to extract the image name from the Url
    $imgFile = [System.IO.Path]::GetFileName($imgUri.LocalPath)

    # build the full path to the target download location
    $imgSaveDestination = Join-Path $downloadFolder $imgFile

Write-Progress -Activity "Bing Downloader" -Status "Attempted Downloads: $i" -CurrentOperation "Downloading Image: $imgSaveDestination"

    $webClient.DownloadFile($imgUri, $imgSaveDestination)
    $i=$i+1

}
$nextpage=$nextpage+27
}
}
