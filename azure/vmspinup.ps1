#Login-AzureRMAccount

Get-AzureRmLocation | sort Location | Select Location

$locName = "centralus"
$rgName = "testgroup"
New-AzureRmResourceGroup -Name $rgName -Location $locName

$stName = "teststorage"
Get-AzureRmStorageAccountNameAvailability $stName

$storageAcc = New-AzureRmStorageAccount -ResourceGroupName $rgName -Name $stName -SkuName "Standard_LRS" -Kind "Storage" -Location $locName

$subnetName = "testsubnet"
$singleSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix 10.0.0.0/24

$vnetName = "testvnet"
$vnet = New-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $rgName -Location $locName -AddressPrefix 10.0.0.0/16 -Subnet $singleSubnet

$ipName = "testip"
$pip = New-AzureRmPublicIpAddress -Name $ipName -ResourceGroupName $rgName -Location $locName -AllocationMethod Dynamic

$nicName = "testnic"
$nic = New-AzureRmNetworkInterface -Name $nicName -ResourceGroupName $rgName -Location $locName -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $pip.Id

$cred = Get-Credential -Message "Type the name and password of the local administrator account."

$vmName = "testvm"
$vm = New-AzureRmVMConfig -VMName $vmName -VMSize "Standard_A1"

$compName = $vmName
$vm = Set-AzureRmVMOperatingSystem -VM $vm -Windows -ComputerName $compName -Credential $cred -ProvisionVMAgent -EnableAutoUpdate

$vm = Set-AzureRmVMSourceImage -VM $vm -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2012-R2-Datacenter -Version "latest"

$vm = Add-AzureRmVMNetworkInterface -VM $vm -Id $nic.Id

$blobPath = "vhds/WindowsVMosDisk.vhd"
$osDiskUri = $storageAcc.PrimaryEndpoints.Blob.ToString() + $blobPath

$diskName = "windowsvmosdisk"
$vm = Set-AzureRmVMOSDisk -VM $vm -Name $diskName -VhdUri $osDiskUri -CreateOption fromImage

New-AzureRmVM -ResourceGroupName $rgName -Location $locName -VM $vm
