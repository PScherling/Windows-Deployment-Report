# 17.04.2024
# pscherling@eurofunk.com
# 
#
# Version 0.1
#
# Changelog:
# 
#
#
# 
################ Deployment Report PowerShell Script ###################### 
## This Script lets creates a report at the end of each deployment		 ## 
##																		 ## 
##                                                                    	 ## 
##																		 ## 
########################################################################### 

#Variables
$global:SysModel = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Model
$global:Model = $global:SysModel.Model
$global:SysName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Name
$global:Hostname = $global:SysName.Name
$global:SysManufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Manufacturer
$global:Manufacturer = $global:SysManufacturer.Manufacturer
$global:SysType = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property SystemType
$global:Systemtype = $global:SysType.SystemType
$global:TimeDate = Get-Date -Format "dd-MM-yyyy"
$global:HRTimeDate = Get-Date -Format "dd.MM.yyyy HH:mm"
$global:FileName = "DeploymentProtocol_"+$global:Hostname+"_"+$global:TimeDate+".html"
$global:FileDir = "C:\_it\DeploymentReport\"
$global:MediaDir = "C:\_it\DeploymentReport\Media\"
$global:FilePath = "$global:FileDir$global:FileName"
$global:FileShare = "\\192.168.121.62\DeploymentShare$\Scripts\DeploymentReport\Media"
$global:ProgressStatus = 0


function StartScript {
    If (-Not ( Test-Path $global:FileDir ))
	{
        #Create Directory
		New-Item -Path "C:\_it\" -Name "DeploymentReport" -ItemType "directory"
    }

    If (-Not ( Test-Path $global:MediaDir ))
	{
        #Create Directory
		New-Item -Path "C:\_it\DeploymentReport\" -Name "Media" -ItemType "directory"
    }

	#Create HTML Report
	If (-Not ( Test-Path $global:FilePath ))
	{
		
		#Copy CSS Stylesheet and Images from DeploymentShare
		Copy-Item -Path "$global:FileShare\*" -Destination $global:MediaDir -Force
		
		#Create File
		New-Item $global:FilePath -ItemType "file" | out-null
		
		#Add Content to the File
		Add-Content $global:FilePath -Value @"
<!doctype html>
<html>
	<head>
		<title>Deployment Report for $global:Hostname</title>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta name="description" content="this is a Report of the configuration from the system after it was deployed."/>
		<meta name="thumbnail" content=""/>
		<link rel="stylesheet" href="Media/styles.css" />
	</head>
	<body>
	<div id="main">
		<div id="title">
			<img id="ef_logo" src="Media/ef_logo.png" alt="EF Logo">
			<h1 id="title">Deployment Report for $global:Hostname</h1>
        </div>
		<h2>System Information</h2>		
        <table>
		<tbody>
		<tr>
		<td>Hostname:</td>
		<td>$global:Hostname</td>
		</tr>
		<tr>
		<td>Date and Time:</td>
		<td>$global:HRTimeDate</td>
		</tr>
		<tr>
		<td>System Type:</td>
		<td>$global:Systemtype</td>
		</tr>
		<tr>
		<td>Manufacturer:</td>
		<td>$global:Manufacturer</td>
		</tr>
		<tr>
		<td>Model:</td>
		<td>$global:Model</td>
		</tr>
        </tbody>
        </table>
"@
	}
	
	#Beginning with getting Data for report
	
	Write-Host "########################################"
	Write-Host "#      Checking Installed Software     #"
	Write-Host "########################################" `n
	Get-InstalledSW
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#            Checking UAC              #"
	Write-Host "########################################" `n
	Get-UACStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#             Checking IPv6            #"
	Write-Host "########################################" `n
	Get-IPv6Setting
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#    Checking First Logon Animation    #"
	Write-Host "########################################" `n
	Get-FirstLogonAnimation
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#    Checking Delayed Desktop Switch   #"
	Write-Host "########################################" `n
	Get-DelayedDesktopSwitch
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#        Checking Administrator        #"
	Write-Host "########################################" `n
	Get-DefAdministratorStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#          Checking PowerPlan          #"
	Write-Host "########################################" `n
	Get-Powerplan
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#      Checking Power Confguration     #"
	Write-Host "########################################" `n
	Get-PowerConfig
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#         Checking WSUS Server         #"
	Write-Host "########################################" `n
	Get-WSUS
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#       Checking WSUS Settings         #"
	Write-Host "########################################" `n
	Get-UseWSUSOptions
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#       Checking sysadmineuro          #"
    Write-Host "#         Password Settings            #"
	Write-Host "########################################" `n
	Get-EFAdminPWExpiracyStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#        Checking RDP Status           #"
	Write-Host "########################################" `n
	Get-RDPStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#      Checking RDP Authentication     #"
	Write-Host "########################################" `n
	Get-RDPAuthentication
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#   Checking RDP in Windows Firewall   #"
	Write-Host "########################################" `n
	Get-RDPFirewallStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#       Checking Windows Firewall      #"
	Write-Host "########################################" `n
	Get-WindowsFirewallStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#   Checking ICMP in Windows Firewall  #"
	Write-Host "########################################" `n
	Get-ICMPFirewallRule
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#          Checking OEM Info           #"
	Write-Host "########################################" `n
	Get-OEMInfo
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#      Checking Location Service       #"
	Write-Host "########################################" `n
	Get-LocationService
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#    Checking Network Localization     #"
	Write-Host "########################################" `n
	Get-NetworkLocalization
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#           Checking WinRM             #"
	Write-Host "########################################" `n
	Get-WinRMStatus
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#         Checking SNMP Feature        #"
	Write-Host "########################################" `n
	Get-SNMPFeature
	#Read-Host "Continue with next step"
	
	Write-Host "########################################"
	Write-Host "#             Checking VSS             #"
	Write-Host "########################################" `n
	Get-VSS
	#Read-Host "Continue with next step"

    Write-Host "########################################"
	Write-Host "#       Checking Active Services       #"
	Write-Host "########################################" `n
    Get-DefaultRunningServices 
	
	Write-Host "########################################"
	Write-Host "#      Checking Installed Drivers      #"
	Write-Host "########################################" `n
	Get-InstalledDriverFirmware
	
	
	#Finish HTML Report
	Add-Content $global:FilePath -Value @"
</div>
</body>
<footer>
</footer>
</html>
"@
	
	#Flush Variables
	$global:SysModel = ""
	$global:Model = ""
	$global:SysName = ""
	$global:Hostname = ""
	$global:SysManufacturer = ""
	$global:Manufacturer = ""
	$global:SysType = ""
	$global:Systemtype = ""
	$global:TimeDate = ""
	$global:HRTimeDate = ""
	$global:FileName = ""
	$global:FilePath = ""
	$global:FileDir = ""
	$global:MediaDir =  ""
	$global:FileShare = ""
	$global:CSSFilePath = ""
	$global:ProgressStatus = ""
}



#Find Installed Software
function Get-InstalledSW {
	#Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName, Publisher #, InstallDate
    $GetSoftware = Get-WmiObject -Class Win32_Product | select Name,Version,Vendor

    $SoftwareNameList = @()
    $SoftwareVersionList = @()
    $SoftwareVendorList = @()

    #Create Table
    Add-Content $global:FilePath -Value @"
    <h2>Installed Software</h2>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Version</th>
    <th>Vendor</th>
    </tr>
"@
    #Fill Table with content
    foreach ($Software in $GetSoftware) {
        $SoftwareNameList += $Software.Name
        $SoftwareVersionList += $Software.Version
        $SoftwareVendorList += $Software.Vendor
    }


    for(($x = 0); $x -lt $SoftwareNameList.Count; $x++) {
        $SWName = $SoftwareNameList[$x]
        $SWVersion = $SoftwareVersionList[$x]
        $SWVendor = $SoftwareVendorList[$x]

        Add-Content $global:FilePath -Value @"
        <tr>
        <td>$SWName</td>
        <td>$SWVersion</td>
        <td>$SWVendor</td>
        </tr>
"@
    }
    
    
    #Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
    #write-output $GetSoftware | fl | out-file $global:FilePath -Append

}


#Check UAC
#Expected: FALSE
function Get-UACStatus {

    [cmdletBinding(SupportsShouldProcess = $true)]

    param(

      [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]

      [string]$Computer

    )

    [string]$RegistryValue = "EnableLUA"

    [string]$RegistryPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"

    [bool]$UACStatus = $false

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)

    $Subkey = $OpenRegistry.OpenSubKey($RegistryPath,$false)

    $Subkey.ToString() | Out-Null

    $UACStatus = ($Subkey.GetValue($RegistryValue) -eq 1)

    #write-host $Subkey.GetValue($RegistryValue)
    #return $UACStatus
    Add-Content $global:FilePath -Value @"
    <h2>User Account Control</h2>
"@
    if ($UACStatus -eq 1) {

        Add-Content $global:FilePath -Value @"
        <p>UAC is enabled.</p>
"@

        #Write-Host "UAC is enabled." -ForegroundColor Green
        
    }
    else {
        Add-Content $global:FilePath -Value @"
        <p>UAC is disabled.</p>
"@
        #Write-Host "UAC is disabled." -ForegroundColor Red
        
    }
}


#Check IPv6
#Expected: Deactivated
function Get-IPv6Setting {
	$Adapter = get-netadapter | select-object Name
    $AdapterName = $Adapter.Name
    $IPv6Setting = get-NetAdapterBinding -ComponentID ms_tcpip6 -Name $AdapterName | select Enabled

    Add-Content $global:FilePath -Value @"
    <h2>IPv6 Network Setting</h2>
"@

    if ($IPv6Setting.Enabled -eq 0) {
        Add-Content $global:FilePath -Value @"
        <p>IPv6 on Network Adapter '$AdapterName' is disabled.</p>
"@
        #Write-Host "IPv6 on Network Adapter '$AdapterName' is disabled." -ForegroundColor Green
    }
    else {
        Add-Content $global:FilePath -Value @"
        <p>IPv6 on Network Adapter '$AdapterName' is enabled.</p>
"@
        #Write-Host "IPv6 on Network Adapter '$AdapterName' is enabled." -ForegroundColor Red
    }
}


#Check Hide Shell Cleanup
#First Logon Animation
#Expected: FALSE
function Get-FirstLogonAnimation {

    [cmdletBinding(SupportsShouldProcess = $true)]

    param(

      [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]

      [string]$Computer

    )

    [string]$RegistryValue = "EnableFirstLogonAnimation"

    [string]$RegistryPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"

    [bool]$AnimationStatus = $false

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)

    $Subkey = $OpenRegistry.OpenSubKey($RegistryPath,$false)

    $Subkey.ToString() | Out-Null

    $AnimationStatus = ($Subkey.GetValue($RegistryValue) -eq 1)

    #write-host $Subkey.GetValue($RegistryValue)
    #return $AnimationStatus

    Add-Content $global:FilePath -Value @"
    <h2>First Logon Animation</h2>
"@

    if ($AnimationStatus -eq 1) {
        Add-Content $global:FilePath -Value @"
        <p>The 'First Logon Animation' is enabled.</p>
"@
        #Write-Host "The 'First Logon Animation' is enabled." -ForegroundColor Red
    }
    else {
        Add-Content $global:FilePath -Value @"
        <p>The 'First Logon Animation' is disabled.</p>
"@
        #Write-Host "The 'First Logon Animation' is disabled." -ForegroundColor Green
    }
}


#Delayed Desktop Switch Timeout
#Expected: FALSE
function Get-DelayedDesktopSwitch {

    [cmdletBinding(SupportsShouldProcess = $true)]

    param(

      [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]

      [string]$Computer

    )

    [string]$RegistryValue = "DelayedDesktopSwitchTimeout"

    [string]$RegistryPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"

    [bool]$DesktopSwitchStatus = $false

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)

    $Subkey = $OpenRegistry.OpenSubKey($RegistryPath,$false)

    $Subkey.ToString() | Out-Null

    $DesktopSwitchStatus = ($Subkey.GetValue($RegistryValue) -eq 1)

    #write-host $Subkey.GetValue($RegistryValue)
    #return $DesktopSwitchStatus

    Add-Content $global:FilePath -Value @"
    <h2>Delayed Desktop Switch</h2>
"@

    if ($DesktopSwitchStatuss -eq 1) {
        Add-Content $global:FilePath -Value @"
        <p>The 'Delayed Desktop Switch' is enabled.</p>
"@
        #Write-Host "The 'Delayed Desktop Switch' is enabled." -ForegroundColor Red
    }
    else {
        Add-Content $global:FilePath -Value @"
        <p>The 'Delayed Desktop Switch' is disabled.</p>
"@
        #Write-Host "The 'Delayed Desktop Switch' is disabled." -ForegroundColor Green
    }
}


#Check if local Administrator User Account is deactivated
#Expected: FALSE
function Get-DefAdministratorStatus {
	$LocalAdmin = Get-LocalUser -Name "Administrator" | select Name,Enabled,Description

    Add-Content $global:FilePath -Value @"
    <h2>Built-in Administrator Account</h2>
"@

    if ($LocalAdmin.Enabled -eq 0) {
        Add-Content $global:FilePath -Value @"
        <p>The Built-in 'Administrator' user account is disabled.</p>
"@
        #Write-Host "The Built-in 'Administrator' user account is disabled." -ForegroundColor Green
    }
    else {
        Add-Content $global:FilePath -Value @"
        <p>The Built-in 'Administrator' user account is enabled.</p>
"@
        #Write-Host "The Built-in 'Administrator' user account is enabled." -ForegroundColor Red
    }
}


#Check Global Power Settings
function Get-Powerplan
{
    function Get-Plan
    {
	    [cmdletbinding()]
	    [OutputType([CimInstance[]])]
	    Param(
		    [Parameter(
			    ValueFromPipeline=$true,
			    ValueFromPipelineByPropertyName=$true, 
			    ValueFromRemainingArguments=$false
		    )]
		    [Alias("ElementName")]
		    [string]$PlanName = "*"
	    )

        Begin
        {
            $f = $MyInvocation.InvocationName
            Write-Verbose -Message "$f - START"
        }

        Process
        {
            if($PlanName)
            {
                Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan | Where-Object ElementName -Like "$PlanName"
            }
            else
            {
                Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan
            }
        }

        End
        {
            Write-Verbose -Message "$f - END"
        }
    }
    $Powerplan = Get-Plan | Select-Object ElementName,Description,IsActive | where-object IsActive -eq 1 #| fl

    $PPlanName = $Powerplan.ElementName
	$PPlanDesc = $Powerplan.Description
	$PPlanActive = $Powerplan.IsActive

    #$Powerplan
	Add-Content $global:FilePath -Value @"
    <h2>PowerPlan Settings</h2>
	<p>Name: </p><p>$PPlanName</p>
	<p>Description: </p><p>$PPlanDesc</p>
	<p>Status: </p><p>$PPlanActive</p>
"@
}


#Check Detailed Power Settings
function Get-PowerConfig
{
	#$Powerplan Settings
	Add-Content $global:FilePath -Value @"
	<h3>Advanced Power Settings</h3>
"@
    function Get-Cfg {

      [CmdletBinding()]
      param(
        [SupportsWildcards()]
        [string] $Scheme, # defaults to the active one
        [switch] $Raw     # request raw powercfg -query output
      )

      if ($env:OS -ne 'Windows_NT') { throw 'This command runs on Windows only.' }

      $settingGuidsToNames = [ordered] @{
        '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' = 'Monitor Timeout'
        '6738e2c4-e8a5-4a42-b16a-e040e769756e' = 'Disk Timeout'
        '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' = 'Standby Timeout'
        '9d7815a6-7ee4-497e-8888-515a05f02364' = 'Hibernate Timeout'
        #'2a737441-1930-4402-8d77-b2bebba308a3' = 'usb_selective_suspend'
      }

      $allSchemes = 
      @(powercfg.exe -list) -ne '' | 
        Select-Object -Skip 2 | 
        ForEach-Object { 
          $null, $guid, $name, $other = ($_ -split '[:()]').Trim()
          [pscustomobject] @{ Name = $name; Guid = $guid; Active = [bool] $other } 
        }

      if (-not $Scheme) {
        $matchingSchemes = $allSchemes.Where({ $_.Active }, 'First')[0]
      }
      elseif ($Scheme -as [guid]) {
        # scheme GUID given
        $matchingSchemes = $allSchemes.Where({ $_.Guid = $Scheme }, 'First')[0]
      }
      else {
        # scheme name given
        $matchingSchemes = $allSchemes | Where-Object Name -Like $Scheme
      }
      if (-not $matchingSchemes) { 
        throw "No power scheme matching '$Scheme' found." 
      }

      foreach ($matchingScheme in $matchingSchemes) {
        $allSettingsText = powercfg.exe -query $matchingScheme.Guid
        
        if ($Raw) { 
            $allSettingsText; continue 
        }
        
        $paragraphs = ($allSettingsText -join "`n") -split '\n{2}' -match '\S'
        
        $out = [ordered] @{} #Scheme = $matchingScheme.Name
        
        $x = 0
        
        $settingGuidsToNames.GetEnumerator() | 
          ForEach-Object {
            $guid = $_.Key
            #Write-Host $guid
            
            $lines = $paragraphs.Where({ $_ -match ('\b{0}\b' -f $guid) }, 'First')[0] -split '\n'
            [Uint32] $acValue, [Uint32] $dcValue = $lines[-2, -1] -replace '^.+: '
            

            $acValue = $acValue / 60
            $dcValue = $dcValue / 60

            if($acValue -eq 0) {
                $acReadValue = "Deactivated"
            }
            elseif($acValue -ne 0) {
                $acReadValue = [string] $acValue+" Minutes"
            }

            if($dcValue -eq 0) {
                $dcReadValue = "Deactivated"
            }
            elseif($dcValue -ne 0) {
                $dcReadValue = [string] $dcValue+" Minutes"
            }

            
            $Setting = $settingGuidsToNames[$x]
            
            $out = $Setting+": AC is "+$acReadValue + " | DC is " + $dcReadValue
            
            #Write-Host $out
			
			#$Powerplan Settings
			Add-Content $global:FilePath -Value @"
			<p>$out</p>
"@
            $x++
          }
      }
    }
    $PowerConfig = Get-Cfg | fl
    #$PowerConfig
	
}




#Check USB Selective Suspend
#TBD



#WSUS Settings
function Get-WSUS {
	$GetWSUSInfo = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | select WUServer,WUStatusServer,ElevateNonAdmins,DoNotConnectToWindowsUpdateInternetLocations,SetUpdateNotificationLevel,UpdateNotificationLevel
	
    #Create Table
    Add-Content $global:FilePath -Value @"
    <h2>WSUS Information</h2>
"@
	
	$WUServer = $GetWSUSInfo.WUServer
	$WUStatusSrv = $GetWSUSInfo.WUStatusServer
    if ($GetWSUSInfo.ElevateNonAdmins -eq 1) {
        $ElevateNonAdmins = "Users in the Users security group are allowed to approve or disapprove updates."
    }
	elseif ($GetWSUSInfo.ElevateNonAdmins -eq 0) {
         $ElevateNonAdmins = "Only users in the Administrators user group can approve or disapprove updates."
    }
    #$ElevateNonAdmins = $GetWSUSInfo.ElevateNonAdmins

    if ($GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
        $InternetConnect = "Connections to public Microsoft services (update service) will no longer be established."
    }
	elseif ($GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 0) {
         $InternetConnect = "Connections to Microsoft services are established at regular intervals. (Default)"
    }
	#$InternetConnect = $GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations

    if ($GetWSUSInfo.SetUpdateNotificationLevel -eq 1) {
        $SetNotificationLevel = "Notifications are enabled."
    }
	elseif ($GetWSUSInfo.SetUpdateNotificationLevel -eq 0) {
         $SetNotificationLevel = "Notifications are disabled."
    }
	#$SetNotificationLevel = $GetWSUSInfo.SetUpdateNotificationLevel

    if ($GetWSUSInfo.UpdateNotificationLevel -eq 1) {
        $UpateNotificationLevel = "Disable all notifications, excluding restart warnings."
    }
	elseif ($GetWSUSInfo.UpdateNotificationLevel -eq 0) {
        $UpateNotificationLevel = "Default OS Windows Update notifications."
    }
    elseif ($GetWSUSInfo.UpdateNotificationLevel -eq 2) {
        $UpateNotificationLevel = "Disable all notifications, including restart warnings."
    }
	#$UpateNotificationLevel = $GetWSUSInfo.UpdateNotificationLevel
	


	#Write-Host "Windows Update Server:" $WUServer
	#Write-Host "Status Server:" $WUStatusSrv
	#Write-Host "NonAdmins Elevation:" $ElevateNonAdmins
	#Write-Host "Do Not Connect to Microsoft Windows Update Internet Locations:" $InternetConnect
	#Write-Host "Set Update Notification Level:" $SetNotificationLevel
	#Write-Host "Update Notification Level:" $UpateNotificationLevel
	

	Add-Content $global:FilePath -Value @"
	<p>Windows Update Server: $WUServer</p>
	<p>Status Server: $WUStatusSrv</p>
	<p>NonAdmins Elevation: $ElevateNonAdmins</p>
	<p>Do Not Connect to Microsoft Windows Update Internet Locations: $InternetConnect</p>
	<p>Set Update Notification Level: $SetNotificationLevel</p>
	<p>Update Notification Level: $UpateNotificationLevel</p>
"@
}


function Get-UseWSUSOptions {
	$GetWSUSSettings = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | select AUOptions,UseWUServer,NoAutoRebootWithLoggedOnUsers,NoAutoUpdate,ScheduledInstallDay,ScheduledInstallTime

    #Create Table
    Add-Content $global:FilePath -Value @"
    <h3>WSUS Advanced Settings</h3>
"@

    if ($GetWSUSSettings.AUOptions -eq 2) {
        $AUOptions = "Notify before download."
    }
	elseif ($GetWSUSSettings.AUOptions -eq 3) {
         $AUOptions = "Automatically download and notify of installation."
    }
    elseif ($GetWSUSSettings.AUOptions -eq 4) {
         $AUOptions = "Automatic download and scheduled installation. (Opnly valid if 'Scheduled Install Settings' are configured!)"
    }
    elseif ($GetWSUSSettings.AUOptions -eq 5) {
         $AUOptions = "Automatic Updates is required, but end users can configure it."
    }

    if ($GetWSUSSettings.UseWUServer -eq 0) {
        $UseWUServer = "The client connects directly to the Windows Update site (http://windowsupdate.microsoft.com) on the Internet."
    }
	elseif ($GetWSUSSettings.UseWUServer -eq 1) {
         $UseWUServer = "The client connects to the specified local update service (WSUS)."
    }

    if ($GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -eq 0) {
        $NoAutoRebootWithLoggedOnUsers = "Automatic Updates notifies user that the computer will restart in 5 minutes."
    }
	elseif ($GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -eq 1) {
         $NoAutoRebootWithLoggedOnUsers = "Logged-on user gets to choose whether or not to restart his or her computer."
    }

    if ($GetWSUSSettings.NoAutoUpdate -eq 0) {
        $NoAutoUpdate = "Automatic Updates are enabled."
    }
	elseif ($GetWSUSSettings.NoAutoUpdate -eq 1) {
         $NoAutoUpdate = "Automatic Updates are disabled."
    }

    if ($GetWSUSSettings.ScheduledInstallDay -eq 0) {
        $ScheduledInstallDay = "Updates will be installed every day."
    }
	elseif ($GetWSUSSettings.ScheduledInstallDay -eq 1) {
         $ScheduledInstallDay = "Updates will be installed on Sunday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 2) {
         $ScheduledInstallDay = "Updates will be installed on Monday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 3) {
         $ScheduledInstallDay = "Updates will be installed on Tuesday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 4) {
         $ScheduledInstallDay = "Updates will be installed on Wednesday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 5) {
         $ScheduledInstallDay = "Updates will be installed on Thursday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 6) {
         $ScheduledInstallDay = "Updates will be installed on Friday."
    }
    elseif ($GetWSUSSettings.ScheduledInstallDay -eq 7) {
         $ScheduledInstallDay = "Updates will be installed on Saturday."
    }

    $Hours = @(0..23)
    #Write-Host $GetWSUSSettings.ScheduledInstallTime

    if ($Hours -contains $GetWSUSSettings.ScheduledInstallTime) {
        $ScheduledInstallTime = "Updates will be installed on a specific time of day."
    }
	elseif ($Hours -notcontains $GetWSUSSettings.ScheduledInstallTime) {
         $ScheduledInstallTime = "This setting is not configred"
    }

    #Write-Host $AUOptions
    #Write-Host $UseWUServer
    #Write-Host $NoAutoRebootWithLoggedOnUsers
    #Write-Host $NoAutoUpdate
    #Write-Host $ScheduledInstallDay
    #Write-Host $ScheduledInstallTime
	
	Add-Content $global:FilePath -Value @"
	<p>Automatic Update Options: $AUOptions</p>
	<p>Windows Update Settings: $UseWUServer</p>
	<p>Atomatic Reboot while Users are logged on: $NoAutoRebootWithLoggedOnUsers</p>
	<p>Automatic Update Setting: $NoAutoUpdate</p>
	<p>Setting on which day updates will be installed: $ScheduledInstallDay</p>
	<p>Setting when updates will be installed on a specific day: $ScheduledInstallTime</p>
"@

}


#Check if Local Admin Pwd Expiration Date is disabled for sysadmineuro
#Expected is TRUE
function Get-EFAdminPWExpiracyStatus {
	$userName = "sysadmineuro"

    $user = Get-LocalUser -Name $userName
    $PWExpireStatus = get-LocalUser -Name $userName | select PasswordExpires
    #Write-Host $PWExpireStatus.PasswordExpires
	

    Add-Content $global:FilePath -Value @"
    <h2>Local Administrator Password Settings</h2>
"@

    if ($PWExpireStatus.PasswordExpires -eq $null) {
        #Write-Host "$userName has 'Password never expires' set to true." -ForegroundColor Green
		
		Add-Content $global:FilePath -Value @"
		<p>User $userName has 'Password never expires' set to true.</p>
"@
    }
    else {
        #Write-Host "$userName has 'Password never expires' set to false." -ForegroundColor Red
		
		Add-Content $global:FilePath -Value @"
		<p>User $userName has 'Password never expires' set to false.</p>
"@
    } 
}


#Check RDP Status
#Expected is ACTIVE
function Get-RDPStatus {
	$RDPStatus = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | select fDenyTSConnections
	
    Add-Content $global:FilePath -Value @"
    <h2>Remote Desktop Protocol Settings</h2>
"@

	if ($RDPStatus.fDenyTSConnections -eq 0) {
		#Write-Host "Remote Desktop Protocol is enabled." -ForegroundColor Green
		
		Add-Content $global:FilePath -Value @"
		<p>Remote Desktop Protocol is enabled.</p>
"@
	}
	else {
		#Write-Host "Remote Desktop Protocol is disabled." -ForegroundColor Red
		
		Add-Content $global:FilePath -Value @"
		<p>Remote Desktop Protocol is disabled.</p>
"@
	}
}

#Check RDP Athentication
#Expected is Disabled
function Get-RDPAuthentication {
	$RDPAuth = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"  | select UserAuthentication
	
	Add-Content $global:FilePath -Value @"
    <h3>RDP Authentication Settings</h3>
"@

	if ($RDPAuth.UserAuthentication -eq 0) {
		#Write-Host "RDP Network-Level user authentication is disabled." -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>RDP Network-Level user authentication is disabled.</p>
"@
	}
	else {
		#Write-Host "RDP Network-Level user authentication is enabled." -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>RDP Network-Level user authentication is enabled.</p>
"@
	}
}

function Get-RDPFirewallStatus {
	$RDPFWRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | select DisplayName,DisplayGroup,Description,Enabled

    $RuleDisplayNameList = @()
    $RuleDisplayGroupList = @()
    $RuleDescriptionList = @()
    $RuleStatusList = @()
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>RDP Firewall Rules</h3>
    <table>
    <tbody>
    <tr>
	<th>Status</th>
    <th>Name</th>
    <th>Group</th>
	<th>Description</th>
    </tr>
"@

    #Fill Table with content
    foreach ($FWRule in $RDPFWRules) {
        $RuleDisplayNameList += $FWRule.DisplayName
        $RuleDisplayGroupList += $FWRule.DisplayGroup
        $RuleDescriptionList += $FWRule.Description
        $RuleStatusList += $FWRule.Enabled
    }

    for(($x = 0); $x -lt $RuleDisplayNameList.Count; $x++) {
        $FWRuleName = $RuleDisplayNameList[$x]
        $FWGroup = $RuleDisplayGroupList[$x]
        $FWRuleDesc = $RuleDescriptionList[$x]
        $FWRuleStat = $RuleStatusList[$x]
		
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$FWRuleStat</td>
        <td>$FWRuleName</td>
		<td>$FWGroup</td>
		<td>$FWRuleDesc</td>
        </tr>
"@

    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check ICMP Firewall Rule
#Expected is Rile exists
function Get-ICMPFirewallRule {
	$ICMPAllowed = Get-NetFirewallRule -DisplayName "ICMP Allow incoming V4 echo request" | select DisplayName,Name,Enabled,Profile
	
	Add-Content $global:FilePath -Value @"
    <h2>ICMP v4 Firewall Rules</h2>
"@
    $ICMPProfile = $ICMPAllowed.Profile
	
    if ($ICMPAllowed.Enabled -eq 'True') {
        #Write-Host "Incoming ICMP V4 echo requests are allowed in '"$ICMPAllowed.Profile"' profile through local firewall." -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
        <p>Incoming ICMP V4 echo requests are allowed in '$ICMPProfile' profile through local firewall.</p>
"@
    }
    else {
        #Write-Host "Incoming ICMP V4 echo requests are not allowed through local firewall." -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
        <p>Incoming ICMP V4 echo requests are not allowed through local firewall.</p>
"@
    }
}

#Check Windows Firewall Status
function Get-WindowsFirewallStatus {
	$FirewallProfiles = Get-NetFirewallProfile | select Name,Enabled

    $FWProfileNameList = @()
    $FWProfileStatusList = @()
	
    #Create Table
    Add-Content $global:FilePath -Value @"
    <h2>Windows Firewall Status</h2>
    <table>
    <tbody>
    <tr>
    <th>Scope</th>
    <th>Enabled</th>
    </tr>
"@

    #Fill Table with content
    foreach ($FWProfile in $FirewallProfiles) {
        $FWProfileNameList += $FWProfile.Name
        $FWProfileStatusList += $FWProfile.Enabled
    }

    for(($x = 0); $x -lt $FWProfileNameList.Count; $x++) {
        $FWProfileName = $FWProfileNameList[$x]
        $FWProfileStatus = $FWProfileStatusList[$x]
		
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$FWProfileName</td>
        <td>$FWProfileStatus</td>
        </tr>
"@

    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}


#Check OEM Info
function Get-OEMInfo {
	
	Add-Content $global:FilePath -Value @"
    <h2>OEM Information</h2>
"@
    #OEM bitmap 
    if(test-path "C:\windows\system32\ef_oem.bmp") {
	    #Write-Host "EF OEM Image is available in 'C:\windows\system32\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is available under 'C:\windows\system32\'.</p>
"@
    }
    else {
        #Write-Host "EF OEM Image file is not available in 'C:\windows\system32\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image file could not be found under 'C:\windows\system32\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\ef_oem.bmp" ) {
	    #Write-Host "EF OEM User Account Image 'ef_oem.bmp' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF OEM User Account Image 'ef_oem.bmp' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF OEM User Account Image 'ef_oem.bmp' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF OEM User Account Image 'ef_oem.bmp' could not be found under 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    #User Account Image files
    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\guest.*") {
        #Write-Host "EF Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user.*") {
        #Write-Host "EF Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-32.png") {
        #Write-Host "EF Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-40.png") {
        #Write-Host "EF Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-48.png") {
        #Write-Host "EF Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-192.png") {
        #Write-Host "EF Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    #OOBE Info
    if(test-path "C:\windows\system32\oobe\info\ef_oem.BMP") {
        #Write-Host "EF OEM Image is available in 'C:\windows\system32\oobe\info\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is available in 'C:\windows\system32\oobe\info\'.</p>
"@
    }
    else {
        #Write-Host "EF OEM Image is not available in 'C:\windows\system32\oobe\info\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is not available in 'C:\windows\system32\oobe\info\'.</p>
"@
    }

    #Backgrounds
    if(test-path "C:\windows\system32\oobe\info\backgrounds\eurofunk_Wallpaper.jpg") {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\windows\system32\oobe\info\backgrounds\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\windows\system32\oobe\info\backgrounds\'.</p>
"@
    }
    else {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in C:\windows\system32\oobe\info\backgrounds\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in C:\windows\system32\oobe\info\backgrounds\'.</p>
"@
    }
    if(test-path "C:\Windows\Web\Wallpaper\Windows\$wallpaper\eurofunk_Wallpaper.jpg") {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\Windows\Web\Wallpaper\Windows\'." `n -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
"@
    }
    else {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in 'C:\Windows\Web\Wallpaper\Windows\'." `n -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
"@
    }

    #required registry changes
    #Write-Host "OEM Registry Values" 
    $OEMValues = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation" | select Manufacturer,Logo
	$OEMManufacturer = $OEMValues.Manufacturer
	$OEMLogo = $OEMValues.Logo
	
	Add-Content $global:FilePath -Value @"
	<h3>OEM Registry Values</h3>
	<p>Manufacturer: $OEMManufacturer</p>
	<p>Logo: $OEMLogo</p>
"@
    #Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" #Cannot find path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' because it does not exist.
}


#Check Location Service
#Expected is Disabled
function Get-LocationService {
	$LocationServiceStatus = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" | select Value
	
	Add-Content $global:FilePath -Value @"
    <h2>Location Service</h2>
"@
    
    if ($LocationServiceStatus.Value -eq 'Deny') {
        #Write-Host "Location Service is disabled." -ForegroundColor Green
		
		Add-Content $global:FilePath -Value @"
		<p>Location Service is disabled.</p>
"@
    }
    else {
        #Write-Host "Location Service is enabled." -ForegroundColor Red
		
		Add-Content $global:FilePath -Value @"
		<p>Location Service is enabled.</p>
"@
    }
}


#Check Network Windows
#Expected is Disabled
function Get-NetworkLocalization {
	Add-Content $global:FilePath -Value @"
    <h2>Network Localization</h2>
"@
    try {	
        $NetworkLocalisation = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
        #Write-Host "Network Localization is disabled." -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>Network Localization is disabled.</p>
"@
    }
    catch {
        #Write-Host "Network Lokalization is enabled." -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>Network Localization is enabled.</p>
"@
    }
    
}


#Check WinRM Status
#Expected is enabled
function Get-WinRMStatus {
	$WinRMSvc = Get-Service -Name "WinRM" | select Status,Name,DisplayName
	
	Add-Content $global:FilePath -Value @"
    <h2>WinRM Service Status</h2>
"@
	
	$WinRMDisplayName = $WinRMSvc.DisplayName
	$WinRMName = $WinRMSvc.Name
	
	
    if ($WinRMSvc.Status -eq 'Running') {
        #Write-Host $WinRMSvc.DisplayName " - " $WinRMSvc.Name "is up and running." -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
		<p>$WinRMDisplayName - $WinRMName is up and running.</p>
"@
    }
    else {
        #Write-Host $WinRMDisplayName " - " $WinRMSvc.Name "is not running" -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>$WinRMDisplayName - $WinRMName is not running.</p>
"@
    }
}


#Check SNMP Feature is Installed
#Expected is true
function Get-SNMPFeature {
	$SNMPFeature = Get-WindowsCapability -Online -Name "SNMP*" | select State,DisplayName,Description
	
	Add-Content $global:FilePath -Value @"
    <h2>SNMP Windows Feature</h2>
"@
    
	$SNMPName = $SNMPFeature.DisplayName
	$SNMPDesc = $SNMPFeature.Description
	
    if ($SNMPFeature.State -eq 'Installed') {
        #Write-Host $SNMPFeature.DisplayName "is installed." -ForegroundColor Green
        #Write-Host $SNMPFeature.Description
		
		Add-Content $global:FilePath -Value @"
		<p>$SNMPName is installed.</p>
		<p>$SNMPDesc is installed.</p>
"@
    }
    else {
        #Write-Host "SNMP is not installed." -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
		<p>SNMP is not installed.</p>
"@
    }
}


#Check VSS
#Expected is C=10% and D=10%
function Get-VSS {
	$VSSonC = vssadmin list shadowstorage /for=C:
	$VSSonD = vssadmin list shadowstorage /for=D:
	
	Add-Content $global:FilePath -Value @"
    <h2>VSS Settings</h2>
"@

    $MaxVSSforC = $VSSonC[-2]
    $MaxVSSforD = $VSSonD[-2]
	
	Add-Content $global:FilePath -Value @"
	<p>Maximum VSS Setting for Volume C: $MaxVSSforC</p>
	<p>Maximum VSS Setting for Volume D: $MaxVSSforD</p>
"@
}

#Get all Default Services that are running on zhe system
function Get-DefaultRunningServices {
	$GetSvc = Get-Service | Where-Object {$_.Status -eq "Running"}
	
	$SVCNameList = @()
    $SVCDescList = @()
    $SVCStateList = @()
	
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h2>Default Active Services</h2>
    <table>
    <tbody>
    <tr>
    <th>State</th>
    <th>Name</th>
    <th>Display Name</th>
    </tr>
"@
    #Fill Table with content
    foreach ($Service in $GetSvc) {
        $SVCNameList += $Service.Name
        $SVCDescList += $Service.DisplayName
        $SVCStateList += $Service.Status
    }


    for(($x = 0); $x -lt $SVCNameList.Count; $x++) {
        $SVCName = $SVCNameList[$x]
        $SVCDesc = $SVCDescList[$x]
        $SVCState = $SVCStateList[$x]

        Add-Content $global:FilePath -Value @"
        <tr>
        <td>$SVCState</td>
        <td>$SVCName</td>
        <td>$SVCDesc</td>
        </tr>
"@
    }
    
    
    #Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}


#Check Installed Drivers and Firmware
function Get-InstalledDriverFirmware {
	$SignedDrivers = Get-WmiObject Win32_PnPSignedDriver | select DeviceName, Manufacturer, DriverVersion
	
	$DeviceNameList = @()
    $ManufacturerList = @()
    $DriverVersionList = @()
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h2>Installed Drivers</h2>
    <table>
    <tbody>
    <tr>
    <th>Device Name</th>
    <th>Manufacturer</th>
    <th>Driver Version</th>
    </tr>
"@

	#Fill Table with content
    foreach ($Driver in $SignedDrivers) {
        $DeviceNameList += $Driver.DeviceName
        $ManufacturerList += $Driver.Manufacturer
        $DriverVersionList += $Driver.DriverVersion
    }
	
	for(($x = 0); $x -lt $DeviceNameList.Count; $x++) {
        $DeviceName = $DeviceNameList[$x]
        $Manufacturer = $ManufacturerList[$x]
        $DriverVersion = $DriverVersionList[$x]
		
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$DeviceName</td>
        <td>$Manufacturer</td>
        <td>$DriverVersion</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}


#Function Call to Start Script
StartScript