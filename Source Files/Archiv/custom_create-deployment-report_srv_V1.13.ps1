<#
.SYNOPSIS
    
.DESCRIPTION
    
.LINK
    
.NOTES
          FileName: custom_create-deployment-report_srv_V1.13.ps1
          Solution: 
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2024-04-26
          Modified: 2025-04-07

          Version - 0.1.0 - () - Finalized functional version 1.
          Version - 0.1.6 - () - Windows Server 25 Adaption and some minor tweaks
		  Version - 0.1.7 - () - CPU Presentation fixed, if there is more than 1 CPU in the system
		  Version - 0.1.8 - () - Adding Logging Features
		  Version - 0.1.9 - () - Minor Bug fixes regarding design of the report.
		  Version - 0.1.10 - () - Adding new Security Checks.
		  Version - 0.1.11 - () - Reorganizing the report.
		  Version - 0.1.12 - () - Adding Progress Information.
		  Version - 0.1.13 - () - Adapting Information gathering of VSS.
		  
          TODO:
		  
		
.Example
#>

<#
# Get Configuration
#>
$config = "DeplyomentReport"

# Report Version
$global:Version = "1.13"

# Log file path and function to log messages
$SrvIP = "192.168.121.66"
$CompName = $env:COMPUTERNAME
$DateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFileName = "Configure_$($config)_$($CompName)_$($DateTime).log"

$logFilePath = "\\$($SrvIP)\Logs$\Custom\Configuration"
$logFile = "$($logFilePath)\$($logFileName)"

$localLogFilePath = "C:\_it"
$localLogFile = "$($localLogFilePath)\$($logFileName)"

function Write-Log {
	param ([string]$Message)
	$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	"$timestamp $Message" | Out-File -FilePath $localLogFile -Append
}

Write-Log "Start Logging."

# Create required directories
Write-Log "Create required directories."
$directories = @(
	"C:\_it"
)

foreach ($dir in $directories) {
	Write-Log "Directory '$dir' already exists."
	If (-not (Test-Path $dir)) { 
		Write-Log "Creating Directory '$dir'."
		try{
			New-Item -Path $dir -ItemType Directory
		}
		catch{
			Write-Log "ERROR: Directory '$dir' could not be created."
		}
	}
}


### Variables ###
# System Info
$global:SysModel = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Model
$global:Model = $global:SysModel.Model
$global:SysName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Name
$global:Hostname = $global:SysName.Name
$global:SysManufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Manufacturer
$global:Manufacturer = $global:SysManufacturer.Manufacturer
$global:SysType = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property SystemType
$global:Systemtype = $global:SysType.SystemType
$global:SerialNumber = (Get-WmiObject -class win32_bios).SerialNumber

# OS Info
$global:OSInfo = Get-ComputerInfo | select OSName,OSDisplayVersion,WindowsVersion,OSVersion #select WindowsProductName,WindowsVersion,OsVersion
$global:WindowsProduct = $global:OSInfo.OSName #$global:OSInfo.WindowsProductName
$global:OSDisplayVersion = $global:OSInfo.OSDisplayVersion
if([string]::IsNullOrEmpty($global:OSDisplayVersion)) { $global:OSDisplayVersion = "24H2" }
$global:WindowsVersion = $global:OSInfo.WindowsVersion
$global:OSVersion = $global:OSInfo.OsVersion

# CPU Info
$global:CPUInfos = Get-WmiObject -class win32_processor -Property name,numberOfCores,NumberOfLogicalProcessors | Select-Object -Property name,numberOfCores,NumberOfLogicalProcessors
$global:CPUName = $global:CPUInfos.name
$global:CPUCores = $global:CPUInfos.numberOfCores
$global:CPULogProc = $global:CPUInfos.NumberOfLogicalProcessors
$global:CPUCount = $global:CPUInfos.Count

# RAM Info
#Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
#(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
$global:RAMInfo = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}

# File Creation
$global:TimeDate = Get-Date -Format "dd-MM-yyyy_HH-mm"
$global:HRTimeDate = Get-Date -Format "dd.MM.yyyy HH:mm"
$global:FileName = $global:Hostname+"_WDSReport_"+$global:TimeDate+".html"
$global:FileDir = "C:\_it\DeploymentReport\"
$global:MediaDir = "C:\_it\DeploymentReport\Media\"
$global:FilePath = "$global:FileDir$global:FileName"
$global:FileShare = "\\$($SrvIP)\DeploymentShare$\Scripts\Custom\DeploymentReport\Media"




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
    <h3>User Account Control</h3>
	<table>
	<tbody>
"@
    if ($UACStatus -eq 1) {

        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>UAC is enabled. &#9989</td>
        </tr>
"@

        #Write-Host "UAC is enabled." -ForegroundColor Green
		Write-Log "UAC is enabled."
        
    }
    else {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>UAC is disabled. &#10060</td>
        </tr>
"@
        #Write-Host "UAC is disabled." -ForegroundColor Red
		Write-Log "ERROR: UAC is disabled."
        
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>UAC is enabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>UAC improves the security of Windows devices by limiting the access that malicious code has to execute with administrator privileges. UAC empowers users to make informed decisions about actions that might affect the stability and security of their device.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check IPv6
#Expected: Deactivated
function Get-IPv6Setting {
	try {
		$Adapter = get-netadapter | select-object Name
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch any network adapter."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch any network adapter.
$_"
	}
	
    $AdapterName = $Adapter.Name
	
	try {
		$IPv6Setting = get-NetAdapterBinding -ComponentID ms_tcpip6 -Name $AdapterName | select Enabled
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch IPv6 setting on any active network adapter."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch IPv6 setting on any active network adapter.
$_"
	}

    Add-Content $global:FilePath -Value @"
    <h3>IPv6 Network Setting</h3>
	<table>
	<tbody>
"@

    if ($IPv6Setting.Enabled -eq 0) {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>IPv6 on Network Adapter '$AdapterName' is disabled. &#9989</td>
        </tr>
"@
        #Write-Host "IPv6 on Network Adapter '$AdapterName' is disabled." -ForegroundColor Green
		Write-Log "IPv6 on Network Adapter '$AdapterName' is disabled."
		
    }
    else {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>IPv6 on Network Adapter '$AdapterName' is enabled. &#10060</td>
        </tr>
"@
        #Write-Host "IPv6 on Network Adapter '$AdapterName' is enabled." -ForegroundColor Red
		Write-Log "ERROR: IPv6 on Network Adapter '$AdapterName' is enabled."
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>IPv6 on Network Adapter '$AdapterName' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Due to troubleshooting network issues and to guarantee proper network functionality with all our services, we disable IPv6 on our network adapters.</td>
	</tr>
    </tbody>
    </table>
"@
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
    <h3>First Logon Animation</h3>
	<table>
	<tbody>
"@

    if ($AnimationStatus -eq 1) {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'First Logon Animation' is enabled. &#10060</td>
        </tr>
"@
        #Write-Host "The 'First Logon Animation' is enabled." -ForegroundColor Red
		Write-Log "ERROR: The 'First Logon Animation' is enabled."
    }
    else {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'First Logon Animation' is disabled. &#9989</td>
        </tr>
"@
        #Write-Host "The 'First Logon Animation' is disabled." -ForegroundColor Green
		Write-Log "The 'First Logon Animation' is disabled."
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>The 'First Logon Animation' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>To reduce the time the deployment takes to finish and speed up the overall logon procedure, we disable the first logon animation.</td>
	</tr>
    </tbody>
    </table>
"@
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
    <h3>Delayed Desktop Switch</h3>
	<table>
	<tbody>
"@

    if ($DesktopSwitchStatuss -eq 1) {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'Delayed Desktop Switch' is enabled. &#10060</td>
        </tr>
"@
        #Write-Host "The 'Delayed Desktop Switch' is enabled." -ForegroundColor Red
		Write-Log "ERROR: The 'Delayed Desktop Switch' is enabled."
    }
    else {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'Delayed Desktop Switch' is disabled. &#9989</td>
        </tr>
"@
        #Write-Host "The 'Delayed Desktop Switch' is disabled." -ForegroundColor Green
		Write-Log "The 'Delayed Desktop Switch' is disabled."
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>The 'Delayed Desktop Switch' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>To reduce the time the deployment takes to finish and speed up the overall logon procedure, we disable the 'Delayed Desktop Switch'.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check if local Administrator User Account is deactivated
#Expected: FALSE
function Get-DefAdministratorStatus {
	try {
		$LocalAdmin = Get-LocalUser -Name "Administrator" | select Name,Enabled,Description
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch information for default administrator user account."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch information for default administrator user account.
$_"
	}

    Add-Content $global:FilePath -Value @"
    <h3>Built-in Administrator Account</h3>
	<table>
	<tbody>
"@

    if ($LocalAdmin.Enabled -eq 0) {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The Built-in 'Administrator' user account is disabled. &#9989</td>
        </tr>
"@
        #Write-Host "The Built-in 'Administrator' user account is disabled." -ForegroundColor Green
		Write-Log "The Built-in 'Administrator' user account is disabled."
    }
    else {
        Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The Built-in 'Administrator' user account is enabled. &#10060</td>
        </tr>
"@
        #Write-Host "The Built-in 'Administrator' user account is enabled." -ForegroundColor Red
		Write-Log "ERROR: The Built-in 'Administrator' user account is enabled."
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>The Built-in 'Administrator' user account should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>The built-in administrator account has a specific and well-known security identifier, and some attacks target that particular SID. Renaming the account doesn't help, because the SID will stay the same. Therefore, the BuiltIn Administrator account should be disbaled.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check if Local Admin Pwd Expiration Date is disabled for sysadmineuro
#Expected is TRUE
function Get-EFAdminPWExpiracyStatus {
	$userName = "sysadmineuro"

	try {
		$user = Get-LocalUser -Name $userName
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch user account information for 'sysadmineuro'."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch user account information for 'sysadmineuro'.
$_"
	}
	
	try {
		$PWExpireStatus = get-LocalUser -Name $userName | select PasswordExpires
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch password expiracy setting for user account 'sysadmineuro'."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch password expiracy setting for user account 'sysadmineuro'.
$_"
	}
    #Write-Host $PWExpireStatus.PasswordExpires
	

    Add-Content $global:FilePath -Value @"
    <h3>Local Administrator Password Settings</h3>
	<table>
	<tbody>
"@

    if ($PWExpireStatus.PasswordExpires -eq $null) {
        #Write-Host "$userName has 'Password never expires' set to true." -ForegroundColor Green
		Write-Log "$userName has 'Password never expires' set to true."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>User $userName has 'Password never expires' set to true. &#9989</td>
        </tr>
"@
    }
    else {
        #Write-Host "$userName has 'Password never expires' set to false." -ForegroundColor Red
		Write-Log "ERROR: $userName has 'Password never expires' set to false."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>User $userName has 'Password never expires' set to false. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>The 'Password never expires' setting should be set to true.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>The local administrative user account password (policy) should be managed via LAPS. Current research strongly indicates that mandated password changes do more harm than good. They drive users to choose weaker passwords, reuse passwords, or update old passwords in ways that are easily guessed by hackers.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check RDP Status
#Expected is ACTIVE
function Get-RDPStatus {
	try {
		$RDPStatus = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | select fDenyTSConnections
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch RDP status information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch RDP status information.
$_"
	}
	
    Add-Content $global:FilePath -Value @"
    <h3>Remote Desktop Protocol Settings</h3>
	<table>
	<tbody>
"@

	if ($RDPStatus.fDenyTSConnections -eq 0) {
		#Write-Host "Remote Desktop Protocol is enabled." -ForegroundColor Green
		Write-Log "Remote Desktop Protocol is enabled."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Protocol is enabled. &#9989</td>
        </tr>
"@
	}
	else {
		#Write-Host "Remote Desktop Protocol is disabled." -ForegroundColor Red
		Write-Log "ERROR: Remote Desktop Protocol is disabled."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Protocol is disabled. &#10060</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>The Remote Desktop Protocol should be enabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Remote Desktop Protocol is used to connect to a PC from a remote device by using the Microsoft Remote Desktop client. RDP Sessions are secured by Group Policy Settings in a domain.</td>
	</tr>
    </tbody>
    </table>
"@
}

#Check RDP Athentication
#Expected is Disabled
function Get-RDPAuthentication {
	try {
		$RDPAuth = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"  | select UserAuthentication
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch RDP Authentication settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch RDP Authentication settings.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h4>RDP Authentication Settings</h4>
	<table>
	<tbody>
"@

	if ($RDPAuth.UserAuthentication -eq 0) {
		#Write-Host "RDP Network-Level user authentication is disabled." -ForegroundColor Green
		Write-Log "RDP Network-Level user authentication is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>RDP Network-Level user authentication is disabled. &#9989</td>
        </tr>
"@
	}
	else {
		#Write-Host "RDP Network-Level user authentication is enabled." -ForegroundColor Red
		Write-Log "ERROR: RDP Network-Level user authentication is enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>RDP Network-Level user authentication is enabled. &#10060</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>RDP Network-Level user authentication should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>RDP Network-Level user authentication restricts access to the PC. If enabled, users have to authenticate themselves to the network before they can connect to the PC. This makes no sense in this state of implementation of the PC. RDP Sessions ae secured by Group Policy Settings in a domain.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check Location Service
#Expected is Disabled
function Get-LocationService {
	try {
		$LocationServiceStatus = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" | select Value
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch 'Location Service' information settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch 'Location Service' information settings.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>Location Service</h3>
	<table>
	<tbody>
"@
    
    if ($LocationServiceStatus.Value -eq 'Deny') {
        #Write-Host "Location Service is disabled." -ForegroundColor Green
		Write-Log "Location Service is disabled."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Location Service is disabled. &#9989</td>
        </tr>
"@
    }
    else {
        #Write-Host "Location Service is enabled." -ForegroundColor Red
		Write-Log "ERROR: Location Service is enabled."
		
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Location Service is enabled. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>Location Service should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>If enabled, Windows will use the device's capabilities to determine your location and will use this location data. This information is provided to 3rd party applications and services. So we recommend to turn this off by default.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check Network Window
#Expected is Disabled
function Get-NetworkLocalization {
	Add-Content $global:FilePath -Value @"
    <h3>New Network Window</h3>
	<table>
	<tbody>
"@
    try {	
        $NetworkLocalisation = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
        #Write-Host "Network Localization is disabled." -ForegroundColor Green
		Write-Log "Network Localization is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Network Localization for 'New Network Windows' is disabled. &#9989</td>
        </tr>
"@
    }
    catch {
        #Write-Host "Network Lokalization is enabled." -ForegroundColor Red
		Write-Log "ERROR: Network Lokalization is enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Network Localization for 'New Network Windows' is enabled. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>Network Localization for 'New Network Windows' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>By default, the first time you connect to a new network (wired or wireless), you will be prompted "Do you want to allow your PC to be discoverable by other PCs and devices on this network?" by the Network Location wizard. So we recommend to turn this off by default.</td>
	</tr>
    </tbody>
    </table>
"@
    
}


#Check WinRM Status
#Expected is enabled
function Get-WinRMStatus {
	try {
		$WinRMSvc = Get-Service -Name "WinRM" | select Status,Name,DisplayName
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WinRM service information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WinRM service information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>WinRM Service Status</h3>
	<table>
	<tbody>
"@
	
	$WinRMDisplayName = $WinRMSvc.DisplayName
	$WinRMName = $WinRMSvc.Name
	
	
    if ($WinRMSvc.Status -eq 'Running') {
        #Write-Host $WinRMSvc.DisplayName " - " $WinRMSvc.Name "is up and running." -ForegroundColor Green
		Write-Log "$($WinRMSvc.DisplayName) - $($WinRMSvc.Name) is up and running."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>$WinRMDisplayName - $WinRMName is up and running. &#9989</td>
        </tr>
"@
    }
    elseif ($WinRMSvc.Status -ne 'Running') {
        #Write-Host $WinRMDisplayName " - " $WinRMSvc.Name "is not running" -ForegroundColor Red
		Write-Log "ERROR: $($WinRMSvc.DisplayName) - $($WinRMSvc.Name) is not running. Current State is: $($WinRMSvc.Status)"
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>$WinRMDisplayName - $WinRMName is not running. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>$WinRMDisplayName - $WinRMName should be enabled and running.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>We need WinRM in our environments for automatization tools like Software deployment and updates/upgrades to do these jobs remotely. Securtity settings are made via GPO settings in domain.</td>
	</tr>
    </tbody>
    </table>
"@
}


#Check SNMP Feature is Installed
#Expected is true
function Get-SNMPFeature {
	#$SNMPFeature = Get-WindowsCapability -Online -Name "SNMP*" | select State,DisplayName,Description
	try{
		$SNMPFeature = Get-WindowsFeature -Name "SNMP-Service" | select Name, InstallState
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch SNMP FoD information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch SNMP FoD information.
$_"
	}
	
	
	Add-Content $global:FilePath -Value @"
    <h3>SNMP Windows Feature on Demand</h3>
"@
    
	#$SNMPName = $SNMPFeature.DisplayName
	#$SNMPDesc = $SNMPFeature.Description
	
	$SNMPName = $SNMPFeature.Name
	#$SNMPState = $SNMPFeature.InstallState
	
    if ($SNMPFeature.InstallState -eq 'Installed') {
		
		<#Add-Content $global:FilePath -Value @"
        <tr>
        <td>Implemented Setting:</td>
        <td>$SNMPName is installed. &#9989</td>
        </tr>
"@#>
		Add-Content $global:FilePath -Value @"
		<p>Name: $SNMPName</p>
		<p>Description: The Microsoft Windows implementation of the Simple Network Management Protocol (SNMP) is used to configure remote devices, monitor network performance, audit network usage, and detect network faults or inappropriate access.</p>
		<p>Status Enabled: SNMP FoD is installed.</p>
"@
		Write-Log "SNMP FoD is installed."
    }
    else {
        #Write-Host "SNMP is not installed." -ForegroundColor Red
		<#Add-Content $global:FilePath -Value @"
        <tr>
        <td>Implemented Setting:</td>
        <td>SNMP is not installed. &#10060</td>
        </tr>
"@#>
		Add-Content $global:FilePath -Value @"
		<p>Name: $SNMPName</p>
		<p>Description: The Microsoft Windows implementation of the Simple Network Management Protocol (SNMP) is used to configure remote devices, monitor network performance, audit network usage, and detect network faults or inappropriate access.</p>
		<p>Status Enabled: SNMP FoD is not installed.</p>
"@
		Write-Log "SNMP FoD is not installed."
    }

    #Finish Table
    <#Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>SNMP is installed.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>The Microsoft Windows implementation of the Simple Network Management Protocol (SNMP) is used to configure remote devices, monitor network performance, audit network usage, and detect network faults or inappropriate access.</td>
    </tr>
    </tbody>
    </table>
"@
#>
}


#Check VSS
#Expected is C=10% and D=10%
function Get-VSS {
	<#
	try {
		$VSSonC = vssadmin list shadowstorage /for=C:
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch VSS information for 'C:'."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch VSS information for 'C:'.
$_"
		$VSSonC = "-"
	}
	
	try {
		$VSSonD = vssadmin list shadowstorage /for=D:
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch VSS information for 'D:'."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch VSS information for 'D:'.
$_"
		$VSSonD = "-"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>VSS Settings</h3>
"@

    $MaxVSSforC = $VSSonC[-2]
    $MaxVSSforD = $VSSonD[-2]
	
	Add-Content $global:FilePath -Value @"
	<p>Maximum VSS Setting for Volume C: $MaxVSSforC</p>
	<p>Maximum VSS Setting for Volume D: $MaxVSSforD</p>
"@
	Write-Log "Maximum VSS Setting for Volume C: $MaxVSSforC"
	Write-Log "Maximum VSS Setting for Volume D: $MaxVSSforD"
	#>
	
	try{
		$volumes = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }  # DriveType 3 means Local Disk
	}
	catch{
		Write-Log "ERROR: Can not fetch volume information. Reason: $_"
		Exit
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>VSS Settings</h3>
"@

	# Loop through each volume
	foreach ($volume in $volumes) {
		
		$driveLetter = $volume.DeviceID
		Write-Log "Get VSS Limit for volume '$($driveLetter)'"

		Write-Log "Fetch current shadow storage settings for the drive."
		try{
			$shadowStorage = vssadmin list shadowstorage /for=$($driveLetter) #| select-string -Pattern "volume: \($driveLetter\)"
		}
		catch{
			Write-Log "ERROR: Can't fetch current shadow storage settings for the drive. Reason: $_"
			Write-Warning "Can't fetch current shadow storage settings for the drive '$($driveLetter)'."
			Write-Warning " Error Message: $_"
		}


		if ($shadowStorage) {
			$MaxVSS = $shadowStorage[-2]
			
			Add-Content $global:FilePath -Value @"
			<p>Maximum VSS Setting for Volume '$($driveLetter)': $MaxVSS</p>
"@
			Write-Log "Maximum VSS Setting for Volume '$($driveLetter)': $MaxVSS"
			
		} else {
			Write-Log "No shadow storage found for volume '$($driveLetter)'."
			$MaxVSS = "-"
			Add-Content $global:FilePath -Value @"
			<p>Maximum VSS Setting for Volume '$($driveLetter)': $MaxVSS</p>
"@
		}

	}
}


function Get-RDPFirewallStatus {
	try {
		$RDPFWRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | select DisplayName,DisplayGroup,Description,Enabled
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch firewall settings for RDP."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch firewall settings for RDP.
$_"
	}

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
		
		Write-Log "Status:        $FWRuleStat"
		Write-Log "Name:          $FWRuleName"
		Write-Log "Group:         $FWGroup"
		Write-Log "Description:   $FWRuleDesc"
		
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
	try {
		$ICMPAllowed = Get-NetFirewallRule -DisplayName "ICMP Allow incoming V4 echo request" | select DisplayName,Name,Enabled,Profile
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch firewall settings for ICMP."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch firewall settings for ICMP.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>ICMP v4 Firewall Rules</h3>
    <table>
    <tbody>
    <tr>
	<th>Status</th>
    <th>Name</th>
	<th>Description</th>
    </tr>
"@
    $ICMPProfile = $ICMPAllowed.Profile
	
    if ($ICMPAllowed.Enabled -eq 'True') {
        #Write-Host "Incoming ICMP V4 echo requests are allowed in '"$ICMPAllowed.Profile"' profile through local firewall." -ForegroundColor Green
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>True</td>
        <td>ICMP Allow incoming V4 echo request</td>
		<td>Incoming ICMP V4 echo requests are allowed in '$ICMPProfile' profile through local firewall.</td>
        </tr>
"@
		Write-Log "Incoming ICMP V4 echo requests are allowed in '$ICMPProfile' profile through local firewall."
    }
    else {
        #Write-Host "Incoming ICMP V4 echo requests are not allowed through local firewall." -ForegroundColor Red
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>False</td>
        <td>ICMP Allow incoming V4 echo request</td>
		<td>Incoming ICMP V4 echo requests are not allowed through local firewall.</td>
        </tr>
"@
		Write-Log "Incoming ICMP V4 echo requests are not allowed through local firewall."
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check Windows Firewall Status
function Get-WindowsFirewallStatus {
	try {
		$FirewallProfiles = Get-NetFirewallProfile | select Name,Enabled
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Firewall information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Firewall information.
$_"
	}

    $FWProfileNameList = @()
    $FWProfileStatusList = @()
	
    #Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Windows Firewall Status</h3>
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
		
		Write-Log "Scope:        $FWProfileName"
		Write-Log "Enabled:      $FWProfileStatus"
		
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

#WSUS Settings
function Get-WSUS {
	try {
		$GetWSUSInfo = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | select WUServer,WUStatusServer,ElevateNonAdmins,DoNotConnectToWindowsUpdateInternetLocations,SetUpdateNotificationLevel,UpdateNotificationLevel
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WSUS information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch WSUS information.
$_"
	}
    #Create Table
    Add-Content $global:FilePath -Value @"
    <h3>WSUS Information</h3>
"@
	
	$WUServer = $GetWSUSInfo.WUServer
	$WUStatusSrv = $GetWSUSInfo.WUStatusServer
    if ($GetWSUSInfo.ElevateNonAdmins -eq 1) {
        $ElevateNonAdmins = "Users in the Users security group are allowed to approve or disapprove updates."
    }
	elseif ($GetWSUSInfo.ElevateNonAdmins -eq 0) {
         $ElevateNonAdmins = "Only users in the Administrators user group can approve or disapprove updates."
    }
    elseif ($GetWSUSInfo.ElevateNonAdmins -ne 0 -and $GetWSUSInfo.ElevateNonAdmins -ne 1) {
        $ElevateNonAdmins = "Not Set."
    }
    #$ElevateNonAdmins = $GetWSUSInfo.ElevateNonAdmins

    if ($GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
        $InternetConnect = "Connections to public Microsoft services (update service) will no longer be established."
    }
	elseif ($GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 0) {
         $InternetConnect = "Connections to Microsoft services are established at regular intervals. (Default)"
    }
    elseif ($GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -ne 0 -and $GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations -ne 1) {
        $InternetConnect = "Not Set."
    }
	#$InternetConnect = $GetWSUSInfo.DoNotConnectToWindowsUpdateInternetLocations

    if ($GetWSUSInfo.SetUpdateNotificationLevel -eq 1) {
        $SetNotificationLevel = "Notifications are enabled."
    }
	elseif ($GetWSUSInfo.SetUpdateNotificationLevel -eq 0) {
         $SetNotificationLevel = "Notifications are disabled."
    }
    elseif ($GetWSUSInfo.SetUpdateNotificationLevel -ne 1 -and $GetWSUSInfo.SetUpdateNotificationLevel -ne 0) {
        $SetNotificationLevel = "Not Set."
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
    elseif ($GetWSUSInfo.UpdateNotificationLevel -ne 1 -and $GetWSUSInfo.UpdateNotificationLevel -ne 0 -and $GetWSUSInfo.UpdateNotificationLevel -ne 2) {
        $UpateNotificationLevel = "Not Set."
    }
	#$UpateNotificationLevel = $GetWSUSInfo.UpdateNotificationLevel
	


	Write-Log "Windows Update Server:                                             $WUServer"
	Write-Log "Status Server:                                                     $WUStatusSrv"
	Write-Log "NonAdmins Elevation:                                               $ElevateNonAdmins"
	Write-Log "Do Not Connect to Microsoft Windows Update Internet Locations:     $InternetConnect"
	Write-Log "Set Update Notification Level:                                     $SetNotificationLevel"
	Write-Log "Update Notification Level:                                         $UpateNotificationLevel"
	

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
	try {
		$GetWSUSSettings = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | select AUOptions,UseWUServer,NoAutoRebootWithLoggedOnUsers,NoAutoUpdate,ScheduledInstallDay,ScheduledInstallTime
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WSUS settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WSUS settings.
$_"
	}
    #Create Table
    Add-Content $global:FilePath -Value @"
    <h4>WSUS Advanced Settings</h4>
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
    elseif ($GetWSUSSettings.AUOptions -ne 2 -and $GetWSUSSettings.AUOptions -ne 3 -and $GetWSUSSettings.AUOptions -ne 4 -and $GetWSUSSettings.AUOptions -ne 5) {
         $AUOptions = "Not Set."
    }

    if ($GetWSUSSettings.UseWUServer -eq 0) {
        $UseWUServer = "The client connects directly to the Windows Update site (http://windowsupdate.microsoft.com) on the Internet."
    }
	elseif ($GetWSUSSettings.UseWUServer -eq 1) {
         $UseWUServer = "The client connects to the specified local update service (WSUS)."
    }
    elseif ($GetWSUSSettings.UseWUServer -ne 0 -and $GetWSUSSettings.UseWUServer -ne 1) {
         $UseWUServer = "Not Set."
    }

    if ($GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -eq 0) {
        $NoAutoRebootWithLoggedOnUsers = "Automatic Updates notifies user that the computer will restart in 5 minutes."
    }
	elseif ($GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -eq 1) {
         $NoAutoRebootWithLoggedOnUsers = "Logged-on user gets to choose whether or not to restart his or her computer."
    }
    elseif ($GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -ne 0 -and $GetWSUSSettings.NoAutoRebootWithLoggedOnUsers -ne 1) {
          $NoAutoRebootWithLoggedOnUsers = "Not Set."
    }


    if ($GetWSUSSettings.NoAutoUpdate -eq 0) {
        $NoAutoUpdate = "Automatic Updates are enabled."
    }
	elseif ($GetWSUSSettings.NoAutoUpdate -eq 1) {
         $NoAutoUpdate = "Automatic Updates are disabled."
    }
    elseif ($GetWSUSSettings.NoAutoUpdate -ne 0 -and $GetWSUSSettings.NoAutoUpdate -ne 1) {
         $NoAutoUpdate = "Not Set."
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
    elseif ($GetWSUSSettings.ScheduledInstallDay -ne 0 -and $GetWSUSSettings.ScheduledInstallDay -ne 1 -and $GetWSUSSettings.ScheduledInstallDay -ne 2 -and $GetWSUSSettings.ScheduledInstallDay -ne 3 -and $GetWSUSSettings.ScheduledInstallDay -ne 4 -and $GetWSUSSettings.ScheduledInstallDay -ne 5 -and $GetWSUSSettings.ScheduledInstallDay -ne 6 -and $GetWSUSSettings.ScheduledInstallDay -ne 7) {
          $ScheduledInstallDay = "Not Set."
    }


    $Hours = @(0..23)
    #Write-Host $GetWSUSSettings.ScheduledInstallTime

    if ($Hours -contains $GetWSUSSettings.ScheduledInstallTime) {
        $ScheduledInstallTime = "Updates will be installed on a specific time of day."
    }
	elseif ($Hours -notcontains $GetWSUSSettings.ScheduledInstallTime) {
         $ScheduledInstallTime = "This setting is not configred."
    }

	Write-Log "Automatic Update Options:                                    $AUOptions"
	Write-Log "Windows Update Settings:                                     $UseWUServer"
	Write-Log "Atomatic Reboot while Users are logged on:                   $NoAutoRebootWithLoggedOnUsers"
	Write-Log "Automatic Update Setting:                                    $NoAutoUpdate"
	Write-Log "Setting on which day updates will be installed:              $ScheduledInstallDay"
	Write-Log "Setting when updates will be installed on a specific day:    $ScheduledInstallTime"
	
	Add-Content $global:FilePath -Value @"
	<p>Automatic Update Options: $AUOptions</p>
	<p>Windows Update Settings: $UseWUServer</p>
	<p>Atomatic Reboot while Users are logged on: $NoAutoRebootWithLoggedOnUsers</p>
	<p>Automatic Update Setting: $NoAutoUpdate</p>
	<p>Setting on which day updates will be installed: $ScheduledInstallDay</p>
	<p>Setting when updates will be installed on a specific day: $ScheduledInstallTime</p>
"@

}


#Check OEM Info
function Get-OEMInfo {
	
	Add-Content $global:FilePath -Value @"
    <h3>OEM Information</h3>
"@
    #OEM bitmap 
    if(test-path "C:\windows\system32\ef_oem.bmp") {
	    #Write-Host "EF OEM Image is available in 'C:\windows\system32\'." `n -ForegroundColor Green
		Write-Log "EF OEM Image is available in 'C:\windows\system32\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is available under 'C:\windows\system32\'.</p>
        <img src="Media/oem/ef_oem.bmp" alt="EF Logo BMP">
"@
    }
    else {
        #Write-Host "EF OEM Image file is not available in 'C:\windows\system32\'." `n -ForegroundColor Red
		Write-Log "EF OEM Image file is not available in 'C:\windows\system32\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image file could not be found under 'C:\windows\system32\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\ef_oem.bmp" ) {
	    #Write-Host "EF OEM User Account Image 'ef_oem.bmp' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF OEM User Account Image 'ef_oem.bmp' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM User Account Image 'ef_oem.bmp' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/ef_oem.bmp" alt="EF Logo BMP">
"@
    }
    else {
        #Write-Host "EF OEM User Account Image 'ef_oem.bmp' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF OEM User Account Image 'ef_oem.bmp' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM User Account Image 'ef_oem.bmp' could not be found under 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    #User Account Image files
    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\guest.*") {
        #Write-Host "EF Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img class="ef-guest" src="Media/oem/UserAccountPictures/guest.bmp" alt="EF Guest BMP">
        <img class="ef-guest" src="Media/oem/UserAccountPictures/guest.png" alt="EF Guest Picture">
"@
    }
    else {
        #Write-Host "EF Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user.*") {
        #Write-Host "EF Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img class="ef-user" src="Media/oem/UserAccountPictures/user.bmp" alt="EF User BMP">
        <img class="ef-user" src="Media/oem/UserAccountPictures/user.png" alt="EF User Picture">
"@
    }
    else {
        #Write-Host "EF Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-32.png") {
        #Write-Host "EF Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-32.png" alt="EF User Picture 32">
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-40.png") {
        #Write-Host "EF Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-40.png" alt="EF User Picture 40">
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-48.png") {
        #Write-Host "EF Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-48.png" alt="EF User Picture 48">
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    if(test-path "C:\ProgramData\Microsoft\User Account Pictures\user-192.png") {
        #Write-Host "EF Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Green
		Write-Log "EF Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-192.png" alt="EF User Picture 192">
"@
    }
    else {
        #Write-Host "EF Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'." `n -ForegroundColor Red
		Write-Log "EF Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-Content $global:FilePath -Value @"
		<p>EF Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

    #OOBE Info
    if(test-path "C:\windows\system32\oobe\info\ef_oem.BMP") {
        #Write-Host "EF OEM Image is available in 'C:\windows\system32\oobe\info\'." `n -ForegroundColor Green
		Write-Log "EF OEM Image is available in 'C:\windows\system32\oobe\info\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is available in 'C:\windows\system32\oobe\info\'.</p>
        <img src="Media/oem/ef_oem.bmp" alt="EF Logo BMP">
"@
    }
    else {
        #Write-Host "EF OEM Image is not available in 'C:\windows\system32\oobe\info\'." `n -ForegroundColor Red
		Write-Log "EF OEM Image is not available in 'C:\windows\system32\oobe\info\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Image is not available in 'C:\windows\system32\oobe\info\'.</p>
"@
    }

    #Backgrounds
    if(test-path "C:\windows\system32\oobe\info\backgrounds\ef_winsrv22_wallpaper.png") {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\windows\system32\oobe\info\backgrounds\'." `n -ForegroundColor Green
		Write-Log "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\windows\system32\oobe\info\backgrounds\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\windows\system32\oobe\info\backgrounds\'.</p>
        <img class="ef-wallpaper" src="Media/oem/ef_winsrv22_wallpaper.png" alt="EF SRV Wallpaper">
"@
    }
    else {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in C:\windows\system32\oobe\info\backgrounds\'." `n -ForegroundColor Red
		Write-Log "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in C:\windows\system32\oobe\info\backgrounds\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'ef_winsrv22_wallpaper.png' is not available in C:\windows\system32\oobe\info\backgrounds\'.</p>
"@
    }
    if(test-path "C:\Windows\Web\Wallpaper\Windows\ef_winsrv22_wallpaper.png") {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\Windows\Web\Wallpaper\Windows\'." `n -ForegroundColor Green
		Write-Log "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\Windows\Web\Wallpaper\Windows\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
        <img class="ef-wallpaper" src="Media/oem/ef_winsrv22_wallpaper.png" alt="EF SRV Wallpaper">
"@
    }
    else {
        #Write-Host "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in 'C:\Windows\Web\Wallpaper\Windows\'." `n -ForegroundColor Red
		Write-Log "EF OEM Wallpaper 'eurofunk_Wallpaper.jpg' is not available in 'C:\Windows\Web\Wallpaper\Windows\'."
		Add-Content $global:FilePath -Value @"
		<p>EF OEM Wallpaper 'ef_winsrv22_wallpaper.png' is not available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
"@
    }

    #required registry changes
    #Write-Host "OEM Registry Values" 
    try{
		$OEMValues = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation" | select Manufacturer,Logo
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch OEM information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch OEM information.
$_"
	}
	$OEMManufacturer = $OEMValues.Manufacturer
	$OEMLogo = $OEMValues.Logo
	
	Add-Content $global:FilePath -Value @"
	<h4>OEM Registry Values</h4>
	<p>Manufacturer: $OEMManufacturer</p>
	<p>Logo: $OEMLogo</p>
"@
    #Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" #Cannot find path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' because it does not exist.
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
	
	try{
		$Powerplan = Get-Plan | Select-Object ElementName,Description,IsActive | where-object IsActive -eq 1 #| fl
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Power Plan information."
		Write-Warning " Error Message: $_"
		$PPlanName = "-"
		$PPlanDesc = "-"
		$PPlanActive = "-"
	}

    $PPlanName = $Powerplan.ElementName
	$PPlanDesc = $Powerplan.Description
	$PPlanActive = $Powerplan.IsActive
	
	Write-Log "PowerPlan Settings"
	Write-Log "Name:                $PPlanName"
	Write-Log "Description:         $PPlanDesc"
	Write-Log "Status Enabled:      $PPlanActive"

    #$Powerplan
	Add-Content $global:FilePath -Value @"
    <h3>PowerPlan Settings</h3>
	<p>Name: $PPlanName</p>
	<p>Description: $PPlanDesc</p>
	<p>Status Enabled: $PPlanActive</p>
"@
}


#Check Detailed Power Settings
function Get-PowerConfig
{
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h4>PowerPlan Options</h4>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Plugged in Power Setting</th>
	<th>On Battery Power Setting</th>
    </tr>
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
        '48e6b7a6-50f5-4782-a5d4-53bb8f07e226' = 'USB Selective Suspend'
      }

    $allSchemes = 
          @(powercfg.exe -list) -ne '' | 
            Select-Object -Skip 2 | 
            ForEach-Object { 
              $null, $guid, $name, $other = ($_ -split '[:()]').Trim()
              [pscustomobject] @{ Name = $name; Guid = $guid; Active = [bool] $other } 
            }

    $allSchemes


    if (-not $Scheme) {
        $matchingSchemes = $allSchemes | where-object Active #.Where({ $_.Active }, 'First')[0]
    }
    elseif ($Scheme -as [guid]) {
        # scheme GUID given
        $matchingSchemes = $allSchemes | Where-Object Guid #.Where({ $_.Guid = $Scheme }, 'First')[0]
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

            $lines = $paragraphs.Where({ $_ -match ('\b{0}\b' -f $guid) }, 'First')[0] -split '\n'
            [Uint32] $acValue, [Uint32] $dcValue = $lines[-2, -1] -replace '^.+: '


            #Check if ID is for Selective USB Suspend (no convertion for Minutes)
            if ($guid -ne '48e6b7a6-50f5-4782-a5d4-53bb8f07e226') {
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
            
            }
            else {

                if($acValue -eq 0) {
                    $acReadValue = "Deactivated"
                }
                elseif($acValue -ne 0) {
                    $acReadValue = "Activated"
                }

                if($dcValue -eq 0) {
                    $dcReadValue = "Deactivated"
                }
                elseif($dcValue -ne 0) {
                    $dcReadValue = "Activated"
                }
            }

            
            $Setting = $settingGuidsToNames[$x]
            
            $out = $Setting+": AC is "+$acReadValue + " | DC is " + $dcReadValue
            
            #Write-Host $out `n
			
            $x++
			
			Write-Log "Name:                        $Setting"
			Write-Log "Plugged in Power Setting:    $acReadValue"
			Write-Log "On Battery Power Setting:    $dcReadValue"
			
			Add-Content $global:FilePath -Value @"
			<tr>
			<td>$Setting</td>
			<td>$acReadValue</td>
			<td>$dcReadValue</td>
			</tr>
"@
			
          }
      }
	}
	try{
		$PowerConfig = Get-Cfg | fl
	}
	catch{
	
		Write-Warning "Something went wrong. Could not fetch Power Configuration information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch Power Configuration information.
$_"
		$PowerConfig = "-"
	
	}
	#$PowerConfig
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
	
}


#Find Installed Software
function Get-InstalledSW {
	#Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName, Publisher #, InstallDate
    #$GetSoftware = Get-WmiObject -Class Win32_Product | select Name,Version,Vendor
	
	#HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* --> Existiert bei Windows 11 IoT LTSC 2024 nicht mehr.... (ObjectNotFound Exception kommt)
	try {
		$ErrorActionPreference = "SilentlyContinue"
		$GetSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | where-object { $_.DisplayName -ne $null -and $_.DisplayVersion -ne $null -and $_.Publisher -ne $null } | Sort-Object -Property DisplayName, DisplayVersion, Publisher #| Format-Table
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch all information for installed software."
		Write-Log "Something went wrong. Could not fetch all information for installed software.
$_"
	}
	
	#Set back to default value 'Continue'
	$ErrorActionPreference = "Continue"
	
	
    $SoftwareNameList = @()
    $SoftwareVersionList = @()
    $SoftwareVendorList = @()

    #Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Installed Software</h3>
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
        $SoftwareNameList += $Software.DisplayName
        $SoftwareVersionList += $Software.DisplayVersion
        $SoftwareVendorList += $Software.Publisher
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

#Find Installed AppX Packages
# Funktioniert leider noch nicht. läuft immer in den Catch rein. Wenn ich den Teil seperat als PS Script ausführe funktioniertes, abe rhier drin nicht....
function Get-InstalledAppX {
	
	#$ErrorActionPreference = "SilentlyContinue"
	
	<#
	try {
		Import-Module Appx
	}
	catch {
		Write-Warning "Something went wrong. Could not import Appx module."
		Write-Warning " Error Message: $_"
	}
	#>
	
	try {
		#$ErrorActionPreference = "SilentlyContinue"
		# Get-AppxPackage -AllUsers | Select Name, PackageFullName, Publisher, Version | fl
		
		$GetAppxSoftware = Get-AppxPackage -AllUsers | Select-Object Name,Architecture,Version,Publisher | Sort-Object Name #-Property Name,Architecture,Version,Publisher #| Format-Table
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch all information for installed AppX applications."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch all information for installed AppX applications.
$_"
	}
	
	#Set back to default value 'Continue'
	#$ErrorActionPreference = "Continue"
	
	
	$AppxNameList = @()
	$AppxArchitectureList = @()
	$AppxPublisherList = @()
	$AppxVersionList = @()

    #Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Installed AppX Software</h3>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
	<th>Architecture</th>
    <th>Version</th>
    <th>Vendor</th>
    </tr>
"@
	#Fill Table with content
    foreach ($AppxApp in $GetAppxSoftware) {
        $AppxNameList += $AppxApp.Name
        $AppxArchitectureList += $AppxApp.Architecture
        $AppxVersionList += $AppxApp.Version
		$AppxPublisherList += $AppxApp.Publisher
    }


    for(($x = 0); $x -lt $AppxNameList.Count; $x++) {
        $AppName = $AppxNameList[$x]
        $AppArchitecture = $AppxArchitectureList[$x]
		$AppVersion = $AppxVersionList[$x]
        $AppVendor = $AppxPublisherList[$x]
		
		# $AppVendor = CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
		# Verwende einen regulären Ausdruck, um alles nach "O=" zu extrahieren 
        if ($AppVendor -match "O=(.*?)(,|$)") 
        {     
            $AppVendor = $matches[1]
            #Write-Output $AppVendor
        } 
        else 
        {     
            Write-Warning "Organization Information is not present."
        }
		

        Add-Content $global:FilePath -Value @"
        <tr>
        <td>$AppName</td>
		<td>$AppArchitecture</td>
        <td>$AppVersion</td>
        <td>$AppVendor</td>
        </tr>
"@
    }
    
    
    #Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@


    #write-output $GetAppxSoftware | fl | out-file $global:FilePath -Append

}

#Check installed Roles and Features
function Get-RoleFeature {
	try{
		$RoleFeature = Get-WindowsFeature | select Name, InstallState | where-object {$_.InstallState -eq "Installed"} | Sort-Object -Property Name, InstallState
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any installed Roles or Features."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch all information for Roles and Features.
$_"
	}
	
	$RFNameList = @()
    $RFStatusList = @()
	
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Installed Windows Roles and Features</h3>
    <table>
    <tbody>
    <tr>
    <th>State</th>
    <th>Name</th>
    </tr>
"@
    #Fill Table with content
    foreach ($Feature in $RoleFeature) {
        $RFNameList += $Feature.Name
        $RFStatusList += $Feature.InstallState
    }


    for(($x = 0); $x -lt $RFNameList.Count; $x++) {
        $FeatureName = $RFNameList[$x]
        $FeatureStatus = $RFStatusList[$x]

        Add-Content $global:FilePath -Value @"
        <tr>
        <td>$FeatureName</td>
        <td>$FeatureStatus</td>
        </tr>
"@
    }
    
    
    #Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}



#Get all Default Services that are running on zhe system
function Get-DefaultRunningServices {
	try {
		$GetSvc = Get-Service | Where-Object {$_.Status -eq "Running"}
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any running service."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any running service.
$_"
	}
	
	$SVCNameList = @()
    $SVCDescList = @()
    $SVCStateList = @()
	
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Default Active Services</h3>
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
	try{
		$SignedDrivers = Get-WmiObject Win32_PnPSignedDriver | select DeviceName, Manufacturer, DriverVersion | where-object { $_.DeviceName -ne $null -and $_.Manufacturer -ne $null -and $_.DriverVersion -ne $null } | Sort-Object -Property DeviceName, Manufacturer, DriverVersion
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any signed and installed driver."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any signed and installed drive.
$_"
	}
	
	$DeviceNameList = @()
    $ManufacturerList = @()
    $DriverVersionList = @()
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Installed Drivers</h3>
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


#Check Volumes
function Get-VolumeInformation {
	try {
		$Volumes = Get-Volume
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any volume information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any volume information.
$_"
	}  


	$VolumeDriveLetterList = @() #$Volumes.DriveLetter
    $VolumeFriendlyNameList = @() #$Volumes.FileSystemLabel
    $VolumeFileSystemList = @() #$Volumes.FileSystem
    #$VolumeFileSystemTypeList = @() #$Volumes.FileSystemType
	$VolumeDriveTypeList = @() #$Volumes.DriveType
	$VolumeHealthStatusList = @() #$Volumes.HealthStatus
	$VolumeOperationalStatusList = @() #$Volumes.OperationalStatus
	#$VolumeRemainingSizeList = @() #$Volumes.SizeRemaining
	$VolumeMaxSizeList = @() #$Volumes.Size
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>System Storage Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Volume Name</th>
    <th>Drive Letter</th>
    <th>File System</th>
	<th>Drive Type</th>
	<th>Status</th>
	<th>Operational</th>
	<th>Max Useable Size</th>
    </tr>
"@

	#Fill Table with content
    foreach ($Volume in $Volumes) {
        
        $VolumeDriveLetterList += $Volume.DriveLetter
        $VolumeFriendlyNameList += $Volume.FileSystemLabel
        $VolumeFileSystemList += $Volume.FileSystem
        #$VolumeFileSystemTypeList += $Volume.FileSystemType
	    $VolumeDriveTypeList += $Volume.DriveType
	    $VolumeHealthStatusList += $Volume.HealthStatus
	    $VolumeOperationalStatusList += $Volume.OperationalStatus
	    #$VolumeRemainingSizeList += $Volume.SizeRemaining
	    $VolumeMaxSizeList += [math]::round(($Volume.Size / 1GB),2)

    }
	
	for(($x = 0); $x -lt $VolumeDriveTypeList.Count; $x++) {
        $DriveLetter = $VolumeDriveLetterList[$x]
		$VolumeName = $VolumeFriendlyNameList[$x]
		$FileSystem = $VolumeFileSystemList[$x]
        #$FilesystemType = $VolumeFileSystemTypeList[$x]
		$DriveType = $VolumeDriveTypeList[$x]
		$HealthStatus = $VolumeHealthStatusList[$x]
		$OperationalStatus = $VolumeOperationalStatusList[$x]
		$VolumeMaxSize = $VolumeMaxSizeList[$x]
		
		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$VolumeName</td>
        <td>$DriveLetter</td>
        <td>$FileSystem</td>
		<td>$DriveType</td>
		<td>$HealthStatus</td>
		<td>$OperationalStatus</td>
		<td>$VolumeMaxSize GB</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check BitLocker
<#
function Get-BitLockerInformation {
    #get-bitlockervolume | select VolumeType,MountPoint,KeyProtector,ProtectionStatus
	

    try {
		$Volumes = get-bitlockervolume | select VolumeType,MountPoint,KeyProtector,ProtectionStatus
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch BitLocker information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch BitLocker information.
$_"
	}
	
    $VolumeTypeList = @()
    $VolumeDriveLetterList = @()
    #$VolumeKeyProtectorList = @()
    $VolumeProtectionStatusList = @()

    #Create Table
    Add-Content $global:FilePath -Value @"
    <h2>BitLocker Status Information</h2>
    <table>
    <tbody>
    <tr>
    <th>Mount Point</th>
    <th>Volume Type</th>
    <th>Protection Status</th>
    </tr>
"@

    #Fill Table with content
    foreach ($Volume in $Volumes) {
        $VolumeTypeList += $Volume. VolumeType
        $VolumeDriveLetterList += $Volume.MountPoint
	    #$VolumeKeyProtectorList += $Volume.KeyProtector
	    $VolumeProtectionStatusList += $Volume.ProtectionStatus
    }
	
    for(($x = 0); $x -lt $VolumeTypeList.Count; $x++) {
        $VolumeType = $VolumeTypeList[$x]
        $MountPoint = $VolumeDriveLetterList[$x]
        #$KeyProtector = $VolumeKeyProtectorList[$x]
        $ProtectionStatus = $VolumeProtectionStatusList[$x]

        Add-Content $global:FilePath -Value @"
        <tr>
        <td>$MountPoint</td>
        <td>$VolumeType</td>
        <td>$ProtectionStatus</td>
        </tr>
"@
    }

    #Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}
#>

#Check Local Users
function Get-LocalUserInformation {
	try {
		$Users = get-localuser
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any local user account information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any local user account information.
$_"
	}


	$UserNameList = @() #$Users.Name
	$UserEnabledList = @() # $Users.Enabled
	$UserDescriptionList = @() #$Users.Description
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Local User Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Enabled</th>
    <th>Description</th>
    </tr>
"@

	#Fill Table with content
	foreach ($LocalUser in $Users) {
			
		$UserNameList += $LocalUser.Name
		$UserEnabledList += $LocalUser.Enabled
		$UserDescriptionList += $LocalUser.Description

	}
	
	for(($x = 0); $x -lt $UserNameList.Count; $x++) {
		$UserName = $UserNameList[$x]
		$Status = $UserEnabledList[$x]
		$UserDescription = $UserDescriptionList[$x]

		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$UserName</td>
        <td>$Status</td>
        <td>$UserDescription</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check Local Groups
function Get-LocalGroupInformation {
	try {
		$Groups = get-localgroup
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any local user group information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any local user group information.
$_"
	}


	$GroupNameList = @() #$Groups.Name
	$GroupDescriptionList = @() #$Groups.Description
	
	#Create Table
    Add-Content $global:FilePath -Value @"
    <h3>Local Group Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Description</th>
    </tr>
"@

	#Fill Table with content
	foreach ($LocalGroup in $Groups) {
			
		$GroupNameList += $LocalGroup.Name
		$GroupDescriptionList += $LocalGroup.Description

	}
	
	for(($x = 0); $x -lt $GroupNameList.Count; $x++) {
		$GroupName = $GroupNameList[$x]
		$GroupDescription = $GroupDescriptionList[$x]

		Add-Content $global:FilePath -Value @"
        <tr>
        <td>$GroupName</td>
        <td>$GroupDescription</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}


<#
# Enhanced Security Compliance
#>
#Check TLS
function Get-TLS {
	# Fetch Information
	# SSL 2.0
	try {
		$ssl2PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
		$ssl2PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
		
		$ssl2ClientValue1 = Get-ItemProperty -Path "$($ssl2PathClient)" -Name "Enabled"
		$ssl2ClientValue2 = Get-ItemProperty -Path "$($ssl2PathClient)" -Name "DisabledByDefault"
		$ssl2ServerValue1 = Get-ItemProperty -Path "$($ssl2PathServer)" -Name "Enabled"
		$ssl2ServerValue2 = Get-ItemProperty -Path "$($ssl2PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch SSL 2.0 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SSL 2.0 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>SSL/TLS Configuration</h3>
	<h4>SSL 2.0 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($ssl2ClientValue1.Enabled -ne "0") {
		Write-Log "SSL 2.0 Client is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client not disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl2ClientValue1.Enabled -eq "0") {
		Write-Log "SSL 2.0 Client is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl2ClientValue2.DisabledByDefault -ne "1") {
		Write-Log "SSL 2.0 Client is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl2ClientValue2.DisabledByDefault -eq "1") {
		Write-Log "SSL 2.0 Client is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl2ServerValue1.Enabled -ne "0") {
		Write-Log "SSL 2.0 Server is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is not disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl2ServerValue1.Enabled -eq "0") {
		Write-Log "SSL 2.0 Server is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl2ServerValue2.DisabledByDefault -ne "1") {
		Write-Log "SSL 2.0 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl2ServerValue2.DisabledByDefault -eq "1") {
		Write-Log "SSL 2.0 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is disabled by default. &#9989</td>
        </tr>
"@
    }
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
	
	
	
	# SSL 3.0
	try {
		$ssl3PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
		$ssl3PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
		
		$ssl3ClientValue1 = Get-ItemProperty -Path "$($ssl3PathClient)" -Name "Enabled"
		$ssl3ClientValue2 = Get-ItemProperty -Path "$($ssl3PathClient)" -Name "DisabledByDefault"
		$ssl3ServerValue1 = Get-ItemProperty -Path "$($ssl3PathServer)" -Name "Enabled"
		$ssl3ServerValue2 = Get-ItemProperty -Path "$($ssl3PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch SSL 3.0 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SSL 3.0 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
	<h4>SSL 3.0 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($ssl3ClientValue1.Enabled -ne "0") {
		Write-Log "SSL 3.0 Client is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl3ClientValue1.Enabled -eq "0") {
		Write-Log "SSL 3.0 Client is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl3ClientValue2.DisabledByDefault -ne "1") {
		Write-Log "SSL 3.0 Client is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl3ClientValue2.DisabledByDefault -eq "1") {
		Write-Log "SSL 3.0 Client is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl3ServerValue1.Enabled -ne "0") {
		Write-Log "SSL 3.0 Server is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl3ServerValue1.Enabled -eq "0") {
		Write-Log "SSL 3.0 Server is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($ssl3ServerValue2.DisabledByDefault -ne "1") {
		Write-Log "SSL 3.0 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($ssl3ServerValue2.DisabledByDefault -eq "1") {
		Write-Log "SSL 3.0 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is disabled by default. &#9989</td>
        </tr>
"@
    }
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@


	
	# TLS 1.0
	try {
		$tls1PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
		$tls1PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
		
		$tls1ClientValue1 = Get-ItemProperty -Path "$($tls1PathClient)" -Name "Enabled"
		$tls1ClientValue2 = Get-ItemProperty -Path "$($tls1PathClient)" -Name "DisabledByDefault"
		$tls1ServerValue1 = Get-ItemProperty -Path "$($tls1PathServer)" -Name "Enabled"
		$tls1ServerValue2 = Get-ItemProperty -Path "$($tls1PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch TLS 1.0 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.0 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
	<h4>TLS 1.0 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($tls1ClientValue1.Enabled -ne "0") {
		Write-Log "TLS 1.0 Client is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1ClientValue1.Enabled -eq "0") {
		Write-Log "TLS 1.0 Client is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1ClientValue2.DisabledByDefault -ne "1") {
		Write-Log "TLS 1.0 Client is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1ClientValue2.DisabledByDefault -eq "1") {
		Write-Log "TLS 1.0 Client is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1ServerValue1.Enabled -ne "0") {
		Write-Log "TLS 1.0 Server is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1ServerValue1.Enabled -eq "0") {
		Write-Log "TLS 1.0 Server is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1ServerValue2.DisabledByDefault -ne "1") {
		Write-Log "TLS 1.0 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1ServerValue2.DisabledByDefault -eq "1") {
		Write-Log "TLS 1.0 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is disabled by default. &#9989</td>
        </tr>
"@
    }
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@

	
	
	# TLS 1.1
	try {
		$tls1_1PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
		$tls1_1PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
		
		$tls1_1ClientValue1 = Get-ItemProperty -Path "$($tls1_1PathClient)" -Name "Enabled"
		$tls1_1ClientValue2 = Get-ItemProperty -Path "$($tls1_1PathClient)" -Name "DisabledByDefault"
		$tls1_1ServerValue1 = Get-ItemProperty -Path "$($tls1_1PathServer)" -Name "Enabled"
		$tls1_1ServerValue2 = Get-ItemProperty -Path "$($tls1_1PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch TLS 1.1 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.1 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
	<h4>TLS 1.1 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($tls1_1ClientValue1.Enabled -ne "0") {
		Write-Log "TLS 1.1 Client is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_1ClientValue1.Enabled -eq "0") {
		Write-Log "TLS 1.1 Client is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_1ClientValue2.DisabledByDefault -ne "1") {
		Write-Log "TLS 1.1 Client is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_1ClientValue2.DisabledByDefault -eq "1") {
		Write-Log "TLS 1.1 Client is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_1ServerValue1.Enabled -ne "0") {
		Write-Log "TLS 1.1 Server is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is enabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_1ServerValue1.Enabled -eq "0") {
		Write-Log "TLS 1.1 Server is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is disabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_1ServerValue2.DisabledByDefault -ne "1") {
		Write-Log "TLS 1.1 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is not disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_1ServerValue2.DisabledByDefault -eq "1") {
		Write-Log "TLS 1.1 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is disabled by default. &#9989</td>
        </tr>
"@
    }
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@

	
	
	# TLS 1.2
	try {
		$tls1_2PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
		$tls1_2PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
		
		$tls1_2ClientValue1 = Get-ItemProperty -Path "$($tls1_2PathClient)" -Name "Enabled"
		$tls1_2ClientValue2 = Get-ItemProperty -Path "$($tls1_2PathClient)" -Name "DisabledByDefault"
		$tls1_2ServerValue1 = Get-ItemProperty -Path "$($tls1_2PathServer)" -Name "Enabled"
		$tls1_2ServerValue2 = Get-ItemProperty -Path "$($tls1_2PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch TLS 1.2 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.2 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
	<h4>TLS 1.2 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($tls1_2ClientValue1.Enabled -ne "1") {
		Write-Log "TLS 1.2 Client is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_2ClientValue1.Enabled -eq "1") {
		Write-Log "TLS 1.2 Client is enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is enabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_2ClientValue2.DisabledByDefault -ne "0") {
		Write-Log "TLS 1.2 Client is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_2ClientValue2.DisabledByDefault -eq "0") {
		Write-Log "TLS 1.2 Client is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is not disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_2ServerValue1.Enabled -ne "1") {
		Write-Log "TLS 1.2 Server is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_2ServerValue1.Enabled -eq "1") {
		Write-Log "TLS 1.2 Server is enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is enabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_2ServerValue2.DisabledByDefault -ne "0") {
		Write-Log "TLS 1.2 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_2ServerValue2.DisabledByDefault -eq "0") {
		Write-Log "TLS 1.2 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is not disabled by default. &#9989</td>
        </tr>
"@
    }
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
	
	
	
	# TLS 1.3
	try {
		$tls1_3PathClient = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
		$tls1_3PathServer = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
		
		$tls1_3ClientValue1 = Get-ItemProperty -Path "$($tls1_3PathClient)" -Name "Enabled"
		$tls1_3ClientValue2 = Get-ItemProperty -Path "$($tls1_3PathClient)" -Name "DisabledByDefault"
		$tls1_3ServerValue1 = Get-ItemProperty -Path "$($tls1_3PathServer)" -Name "Enabled"
		$tls1_3ServerValue2 = Get-ItemProperty -Path "$($tls1_3PathServer)" -Name "DisabledByDefault"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch TLS 1.3 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.3 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
	<h4>TLS 1.3 Configuration</h4>
	<table>
	<tbody>
"@
	
	if ($tls1_3ClientValue1.Enabled -ne "1") {
		Write-Log "TLS 1.3 Client is not enabled. Value: $tls1_3ClientValue1"
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_3ClientValue1.Enabled -eq "1") {
		Write-Log "TLS 1.3 Client is enabled. Value: $tls1_3ClientValue1"
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is enabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_3ClientValue2.DisabledByDefault -ne "0") {
		Write-Log "TLS 1.3 Client is disabled by default. Value: $tls1_3ClientValue2"
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_3ClientValue2.DisabledByDefault -eq "0") {
		Write-Log "TLS 1.3 Client is not disabled by default. Value: $tls1_3ClientValue2"
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is not disabled by default. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_3ServerValue1.Enabled -ne "1") {
		Write-Log "TLS 1.3 Server is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is disabled. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_3ServerValue1.Enabled -eq "1") {
		Write-Log "TLS 1.3 Server is enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is enabled. &#9989</td>
        </tr>
"@
    }
	
	if ($tls1_3ServerValue2.DisabledByDefault -ne "0") {
		Write-Log "TLS 1.3 Server is disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is disabled by default. &#10060</td>
        </tr>
"@

    }
    elseif ($tls1_3ServerValue2.DisabledByDefault -eq "0") {
		Write-Log "TLS 1.3 Server is not disabled by default."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is not disabled by default. &#9989</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check LLMNR
function Get-LLMNR {
	try {
		$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information.
$_"
	}
	
	try {
		$regValue = Get-ItemProperty -Path "$($regPath)" -Name "EnableMulticast"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information.
$_"
	}
	
	
	Add-Content $global:FilePath -Value @"
    <h3>Link-Local Multicast Resolution (LLMNR) Configuration</h3>
	<table>
	<tbody>
"@
	
	if ($regValue.EnableMulticast -eq "0") {
		Write-Log "Link-Local Multicast Resolution (LLMNR) is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Link-Local Multicast Resolution (LLMNR) is disabled. &#9989</td>
        </tr>
"@
    }
	else{ #($regValue -ne "0") {
		Write-Log "Link-Local Multicast Resolution (LLMNR) is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Link-Local Multicast Resolution (LLMNR) is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>Link-Local Multicast Resolution (LLMNR) should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Link-Local Multicast Name Resolution (LLMNR) is a protocol based on the Domain Name System (DNS) packet format that allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link.</td>
	</tr>
    </tbody>
    </table>
"@
}

#Check WDigest
function Get-WDigest {
	try {
		$regPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WDigest Credential Caching information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WDigest Credential Caching information.
$_"
	}
	
	try {
		$regValue = Get-ItemProperty -Path "$($regPath)" -Name "UseLogonCredential"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WDigest Credential Caching information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WDigest Credential Caching information.
$_"
	}
	
	
	Add-Content $global:FilePath -Value @"
    <h3>WDigest Credential Caching Configuration</h3>
	<table>
	<tbody>
"@
	
	if ($regValue.UseLogonCredential -eq "0") {
		Write-Log "WDigest Credential Caching is disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>WDigest Credential Caching is disabled. &#9989</td>
        </tr>
"@
    }
	else{ #($regValue -ne "0") {
		Write-Log "WDigest Credential Caching is not disabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>WDigest Credential Caching is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>WDigest Credential Caching should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>WDigest Caching is an old technology (but still used) used to store (cache) the passwords of the logged in users  in the memory and use it to negotiate the authentication on the network.</td>
	</tr>
    </tbody>
    </table>
"@
}

#Check LSASS
function Get-LSASS {
	try {
		$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch LSASS information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch LSASS information.
$_"
	}
	
	try {
		$regValue = Get-ItemProperty -Path "$($regPath)" -Name "RunAsPPL"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch LSASS information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch LSASS information.
$_"
	}
	
	
	Add-Content $global:FilePath -Value @"
    <h3>LSASS Configuration</h3>
	<table>
	<tbody>
"@
	
	if ($regValue.RunAsPPL -eq "1") {
		Write-Log "LSASS is running as a protected process."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>LSASS is running as a protected process. &#9989</td>
        </tr>
"@
    }
	else{ #($regValue -ne "1") {
		Write-Log "LSASS is not running as a protected process."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>LSASS is not running as a protected process. &#10060</td>
        </tr>
"@

    }
    
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>LSASS should be running as a protected process.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>This feature aims to prevent unauthorized access, memory reading, and code injection by non-protected processes. By enabling LSA protection, administrators can reinforce the security measures surrounding user credentials, ensuring that they remain confidential and safeguarded against potential threats.</td>
	</tr>
    </tbody>
    </table>
"@
}

#Check SMBv3
function Get-SMB3 {
	try{
		$currentSignature = Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Signature information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Signature information.
$_"
	}
	
	try{
		$currentEncryption = Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Encryption information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Encryption information.
$_"
	}
	
	try{
		$currentSecurity = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Security information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Security information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>SMBv3 Configuration</h3>
	<table>
	<tbody>
"@


	
	if ($currentSignature -ne $true) {
		Write-Log "SMBv3 Signature configuration is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Signature configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 Signature configuration is already enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Signature configuration is active. &#9989</td>
        </tr>
"@
	}

	
	if ($currentEncryption -ne $true) {
		Write-Log "SMBv3 encryption is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Encryption configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 encryption is already enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Encryption configuration is active. &#9989</td>
        </tr>
"@
	}

    
	if ($currentSecurity -ne $true) {
		Write-Log "SMBv3 security is not enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Security configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 security is already enabled."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Security configuration is active. &#9989</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
    </tbody>
    </table>
"@
}

#Check SMBv1
function Get-SMB1 {
	try{
		$smbv1Status = Get-WindowsFeature FS-SMB1
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv1 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv1 information.
$_"
	}
	
	Add-Content $global:FilePath -Value @"
    <h3>SMBv1 Configuration</h3>
	<table>
	<tbody>
"@
	
	if ($smbv1Status.Installed) {
		Write-Log "SMBv1 is installed."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv1 is installed. &#10060</td>
        </tr>
"@
		
	} else {
		Write-Log "SMBv1 is not installed. Nothing to do."
		Add-Content $global:FilePath -Value @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv1 is not installed. &#9989</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-Content $global:FilePath -Value @"
	<tr>
	<td>Expected Setting:</td>
	<td>SMBv1 should not be installed.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>SMB (Server Message Block) is a network-layered protocol mainly used on Windows for sharing files, printers, and communication between network-attached computers.</td>
	</tr>
    </tbody>
    </table>
"@
}





### Final Steps ###
function ConvertToPDF {

    #$reportPath = "C:\_it\DeploymentReport\" #equal to $global:FileDir
	$reportname = Get-ChildItem -Path C:\_it\DeploymentReport\*.html -Name
    $filename = $reportname -split ".html" | select -First 1
	$htmlPath = "$global:FileDir$filename.html"
	$pdfPath = "$global:FileDir$filename.pdf"

    

    Write-Host $reportname
    Write-Host $filename
    Write-Host $htmlPath
    Write-Host $pdfPath

    Start-Sleep 5
	
	Start-Process "msedge.exe" -ArgumentList @("--headless","--print-to-pdf=""$pdfPath""","--disable-extensions","--no-pdf-header-footer","--disable-popup-blocking","--run-all-compositor-stages-before-draw","--disable-checker-imaging", "file:///$htmlPath")
   
	Start-Sleep 5
}

function FlushVariables {
	
    Start-Sleep 5
	#Flush Variables
	# System Info
	$global:SysModel = ""
	$global:Model = ""
	$global:SysName = ""
	$global:Hostname = ""
	$global:SysManufacturer = ""
	$global:Manufacturer = ""
	$global:SysType = ""
	$global:Systemtype = ""
	$global:SerialNumber = ""

	# OS Info
	$global:OSInfo = ""
	$global:WindowsProduct = ""
	$global:OSDisplayVersion = ""
	$global:WindowsVersion = ""
	$global:OSVersion = ""

	# CPU Info
	$global:CPUInfos = ""
	$global:CPUName = ""
	$global:CPUCores = ""
	$global:CPULogProc = ""

	# RAM Info
	$global:RAMInfo = ""

	# File Creation
	$global:TimeDate = ""
	$global:HRTimeDate = ""
	$global:FileName = ""
	$global:FileDir = ""
	$global:MediaDir = ""
	$global:FilePath = ""
	$global:FileShare = ""

	# Report Version
	$global:Version = ""
	
	Write-Warning "
	IMPORTANT! Do not forget to enable 'Secure Boot' in the systems UEFI Security settings after completion of the deployment.
	"
}

function StartScript {
    
    #Wait 10 Seconds - System needs to start background services etc. after foregoing reboot.
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Generating Report:" -PercentComplete 0
    Start-Sleep -Seconds 10

    If (-Not ( Test-Path $global:FileDir ))
	{
        #Create Directory
		Write-Log "Create Directory 'DeploymentReport'."
		New-Item -Path "C:\_it\" -Name "DeploymentReport" -ItemType "directory"
    }

    If (-Not ( Test-Path $global:MediaDir ))
	{
        #Create Directory
		Write-Log "Create Directory 'Media'."
		New-Item -Path "C:\_it\DeploymentReport\" -Name "Media" -ItemType "directory"
    }

	#Create HTML Report
	Write-Log "Create HTML Report."
	If (-Not ( Test-Path $global:FilePath ))
	{
		
		#Copy CSS Stylesheet and Images from DeploymentShare
		Write-Log "Copy CSS Stylesheet and Images from DeploymentShare."
		Copy-Item -Path "$global:FileShare\*" -Destination $global:MediaDir -Recurse -Force
		
		#Create File
		Write-Log "Create File."
		New-Item $global:FilePath -ItemType "file" | out-null
		
		#Add Content to the File
		Write-Log "Add Content to the File."
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
			<img id="ef_logo" src="Media/eurofunk_logo.png" alt="EF Logo">
			<h1 id="title">Deployment Report for $global:Hostname</h1>
			<table id="report-info">
			<tbody>
			<tr>
			<td>Report Template Version:</td>
			<td>Version $global:Version</td>
			</tr>
			<tr>
			<td>Time of Creation:</td>
			<td>$global:HRTimeDate</td>
			</tr>
			</tbody>
			</table>
        </div>
		<h2>System Information</h2>		
        <table>
		<tbody>
		<tr>
		<td>Hostname:</td>
		<td>$global:Hostname</td>
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
		<tr>
		<td>Serial Number:</td>
		<td>$global:SerialNumber</td>
		</tr>
"@

	    $CPUid = @()	
        if($global:CPUCount -gt 1)
		{
            
            for($x=0;$x -lt $global:CPUCount;$x++)
            {
                $CPUid = $x
                $CPUName = $global:CPUName[$x]
                $CPUCores = $global:CPUCores[$x]
                $CPULogProc = $global:CPULogProc[$x]

                Add-Content $global:FilePath -Value @"
        <tr>
        <td>CPU $CPUid</td>
"@
				
				Add-Content $global:FilePath -Value @"
        <td>
        <table class="nested">
        <tr>
		<td>CPU:</td>
		<td>$CPUName</td>
		</tr>
		<tr>
		<td>CPU Cores:</td>
		<td>$CPUCores</td>
		</tr>
		<tr>
		<td>CPU Logical Processors:</td>
		<td>$CPULogProc</td>
		</tr>
        </table>
        </td>
		</tr>
"@
            }
            
		}
		else {
			$CPUid = 0
			Add-Content $global:FilePath -Value @"
		<tr>
        <td>CPU $CPUid</td>
		<td>
        <table class="nested">
        <tr>
		<td>CPU:</td>
		<td>$global:CPUName</td>
		</tr>
		<tr>
		<td>CPU Cores:</td>
		<td>$global:CPUCores</td>
		</tr>
		<tr>
		<td>CPU Logical Processors:</td>
		<td>$global:CPULogProc</td>
		</tr>
		</table>
        </td>
		</tr>
"@
		}
		
		
		Add-Content $global:FilePath -Value @"
		<tr>
		<td>RAM:</td>
		<td>$global:RAMInfo GB</td>
		</tr>
		<tr>
		<td>OS:</td>
		<td>$global:WindowsProduct</td>
		</tr>
		<tr>
		<td>OS Version:</td>
		<td>$global:OSDisplayVersion</td>
		</tr>
		<tr>
		<td>OS Build:</td>
		<td>$global:OSVersion</td>
		</tr>
		<tr>
		<td>OS ReleaseID:</td>
		<td>$global:WindowsVersion</td>
		</tr>
        </tbody>
        </table>
"@
	}
	
	
	
	Add-Content $global:FilePath -Value @"
	<h2>OS Security Configuration</h2>
"@
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking UAC:" -PercentComplete 2
	#Beginning with getting Data for report
	Write-Host "########################################"
	Write-Host "# Checking UAC"
	Write-Host "########################################" `n
	Write-Log "Checking UAC."
	Get-UACStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking TLS:" -PercentComplete 5
	Write-Host "########################################"
	Write-Host "# Checking TLS"
	Write-Host "########################################" `n
	Write-Log "Checking TLS."
	Get-TLS
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking LLMNR:" -PercentComplete 8
	Write-Host "########################################"
	Write-Host "# Checking LLMNR"
	Write-Host "########################################" `n
	Write-Log "Checking LLMNR."
	Get-LLMNR
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WDigest:" -PercentComplete 11
	Write-Host "########################################"
	Write-Host "# Checking WDigest"
	Write-Host "########################################" `n
	Write-Log "Checking WDigest."
	Get-WDigest
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking LSASS:" -PercentComplete 14
	Write-Host "########################################"
	Write-Host "# Checking LSASS"
	Write-Host "########################################" `n
	Write-Log "Checking LSASS."
	Get-LSASS
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SMBv1:" -PercentComplete 17
	Write-Host "########################################"
	Write-Host "# Checking SMBv1"
	Write-Host "########################################" `n
	Write-Log "Checking SMBv1."
	Get-SMB1
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SMBv3:" -PercentComplete 20
	Write-Host "########################################"
	Write-Host "# Checking SMBv3"
	Write-Host "########################################" `n
	Write-Log "Checking SMBv3."
	Get-SMB3
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Built-In Administrator:" -PercentComplete 22
	Write-Host "########################################"
	Write-Host "# Checking Administrator"
	Write-Host "########################################" `n
	Write-Log "Checking Built-In Administrator."
	Get-DefAdministratorStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking sysadmineuro:" -PercentComplete 25
	Write-Host "########################################"
	Write-Host "# Checking sysadmineuro"
    Write-Host "# Password Settings"
	Write-Host "########################################" `n
	Write-Log "Checking sysadmineuro Password Settings."
	Get-EFAdminPWExpiracyStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP Status:" -PercentComplete 28
	Write-Host "########################################"
	Write-Host "# Checking RDP Status"
	Write-Host "########################################" `n
	Write-Log "Checking RDP Status."
	Get-RDPStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP Authentication:" -PercentComplete 31
	Write-Host "########################################"
	Write-Host "# Checking RDP Authentication"
	Write-Host "########################################" `n
	Write-Log "Checking RDP Authentication."
	Get-RDPAuthentication
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Location Service:" -PercentComplete 34
	Write-Host "########################################"
	Write-Host "# Checking Location Service"
	Write-Host "########################################" `n
	Write-Log "Checking Location Service."
	Get-LocationService
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Network Localization:" -PercentComplete 37
	Write-Host "########################################"
	Write-Host "# Checking Network Localization"
	Write-Host "########################################" `n
	Write-Log "Checking Network Localization."
	Get-NetworkLocalization
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WinRM Service:" -PercentComplete 40
	Write-Host "########################################"
	Write-Host "# Checking WinRM"
	Write-Host "########################################" `n
	Write-Log "Checking WinRM."
	Get-WinRMStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SNMP Feature:" -PercentComplete 42
	Write-Host "########################################"
	Write-Host "# Checking SNMP Feature"
	Write-Host "########################################" `n
	Write-Log "Checking SNMP Feature."
	Get-SNMPFeature
	
	
	
	Add-Content $global:FilePath -Value @"
	<h2>Firewall Configuration</h2>
"@

	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP in Windows Firewall:" -PercentComplete 45
	Write-Host "########################################"
	Write-Host "# Checking RDP in Windows Firewall"
	Write-Host "########################################" `n
	Write-Log "Checking RDP in Windows Firewall."
	Get-RDPFirewallStatus
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking ICMP in Windows Firewall:" -PercentComplete 48
	Write-Host "########################################"
	Write-Host "# Checking ICMP in Windows Firewall"
	Write-Host "########################################" `n
	Write-Log "Checking ICMP in Windows Firewall."
	Get-ICMPFirewallRule
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Windows Firewall:" -PercentComplete 51
	Write-Host "########################################"
	Write-Host "# Checking Windows Firewall"
	Write-Host "########################################" `n
	Write-Log "Checking Windows Firewall."
	Get-WindowsFirewallStatus
	
	
	
	Add-Content $global:FilePath -Value @"
	<h2>OS Adjustments</h2>
"@
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking IPv6:" -PercentComplete 54
	Write-Host "########################################"
	Write-Host "# Checking IPv6"
	Write-Host "########################################" `n
	Write-Log "Checking IPv6."
	Get-IPv6Setting
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking First Logon Animation:" -PercentComplete 57
	Write-Host "########################################"
	Write-Host "# Checking First Logon Animation"
	Write-Host "########################################" `n
	Write-Log "Checking First Logon Animation."
	Get-FirstLogonAnimation
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Delayed Desktop Switch:" -PercentComplete 60
	Write-Host "########################################"
	Write-Host "# Checking Delayed Desktop Switch"
	Write-Host "########################################" `n
	Write-Log "Checking Delayed Desktop Switch."
	Get-DelayedDesktopSwitch
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WSUS Server:" -PercentComplete 62
	Write-Host "########################################"
	Write-Host "# Checking WSUS Server"
	Write-Host "########################################" `n
	Write-Log "Checking WSUS Server."
	Get-WSUS
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WSUS Settings:" -PercentComplete 65
	Write-Host "########################################"
	Write-Host "# Checking WSUS Settings"
	Write-Host "########################################" `n
	Write-Log "Checking WSUS Settings."
	Get-UseWSUSOptions
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking OEM Info:" -PercentComplete 68
	Write-Host "########################################"
	Write-Host "# Checking OEM Info"
	Write-Host "########################################" `n
	Write-Log "Checking OEM Info."
	Get-OEMInfo
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking PowerPlan:" -PercentComplete 71
	Write-Host "########################################"
	Write-Host "# Checking PowerPlan"
	Write-Host "########################################" `n
	Write-Log "Checking PowerPlan."
	Get-Powerplan
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Power Confguration:" -PercentComplete 74
	Write-Host "########################################"
	Write-Host "# Checking Power Confguration"
	Write-Host "########################################" `n
	Write-Log "Checking Power Confguration."
	Get-PowerConfig
	
	
	
	Add-Content $global:FilePath -Value @"
	<h2>Storage Information</h2>
"@
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Volume Information:" -PercentComplete 77
	Write-Host "########################################"
	Write-Host "# Checking Volume Information"
	Write-Host "########################################" `n
	Write-Log "Checking Volume Information."
	Get-VolumeInformation
	
	<#Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking BitLocker Information:" -PercentComplete 80
	Write-Host "########################################"
	Write-Host "# Checking BitLocker Information"
	Write-Host "########################################" `n
	Write-Log "Checking BitLocker Information."
	Get-BitLockerInformation
	#>
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking VSS:" -PercentComplete 82
	Write-Host "########################################"
	Write-Host "# Checking VSS"
	Write-Host "########################################" `n
	Write-Log "Checking VSS ."
	Get-VSS
	
	
	Add-Content $global:FilePath -Value @"
	<h2>Local User & Groups</h2>
"@
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Local User Information:" -PercentComplete 85
	Write-Host "########################################"
	Write-Host "# Checking Local User Information"
	Write-Host "########################################" `n
	Write-Log "Checking Local User Information."
	Get-LocalUserInformation
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Local Group Information:" -PercentComplete 88
	Write-Host "########################################"
	Write-Host "# Checking Local Group Information"
	Write-Host "########################################" `n
	Write-Log "Checking Local Group Information."
	Get-LocalGroupInformation
	
	
	Add-Content $global:FilePath -Value @"
	<h2>Software & Windows Features</h2>
"@
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Installed Software:" -PercentComplete 90
	Write-Host "########################################"
	Write-Host "# Checking Installed Software"
	Write-Host "########################################" `n
	Write-Log "Checking Installed Software."
	Get-InstalledSW
	<#
	Write-Host "########################################"
	Write-Host "# Checking Installed AppX Packages"
	Write-Host "########################################" `n
	Write-Log "Checking Installed AppX Packages."
	Get-InstalledAppX
	#>
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Installed Roles & Features:" -PercentComplete 92
	Write-Host "########################################"
	Write-Host "#      Checking Installed Roles        #"
	Write-Host "#			and Features			   #"
	Write-Host "########################################" `n
	Write-Log "Checking Installed Roles and Features."
	Get-RoleFeature
	
	
	Add-Content $global:FilePath -Value @"
	<h2>System Services</h2>
"@

	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Active Services:" -PercentComplete 93
	Write-Host "########################################"
	Write-Host "# Checking Active Services"
	Write-Host "########################################" `n
	Write-Log "Checking Active Services."
    Get-DefaultRunningServices 
	
	
	Add-Content $global:FilePath -Value @"
	<h2>Installed Drivers</h2>
"@
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Installed Drivers:" -PercentComplete 95
	Write-Host "########################################"
	Write-Host "# Checking Installed Drivers"
	Write-Host "########################################" `n
	Write-Log "Checking Installed Drivers."
	Get-InstalledDriverFirmware
	
	
	#Finish HTML Report
	Add-Content $global:FilePath -Value @"
</div>
</body>
<footer>
</footer>
</html>
"@

	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Convert To PDF:" -PercentComplete 97
	Write-Host "########################################"
	Write-Host "# Convert To PDF"
	Write-Host "########################################" `n
	Write-Log "Convert To PDF."
	ConvertToPDF
	
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Flush Variables:" -PercentComplete 98
    Write-Host "########################################"
	Write-Host "# Flush Variables"
	Write-Host "########################################" `n
	Write-Log "Flush Variables."
	FlushVariables
	
}




###### Function Calls ######
StartScript

<#
# Finalizing
#>
Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 98
Write-Log "Finish Logging."
# Upload logFile
try{
	Copy-Item "$localLogFile" -Destination "$logFilePath"
}
catch{
	Write-Warning "ERROR: Logfile '$localLogFile' could not be uploaded to Deployment-Server.
	Reason: $_"
}
Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 99
# Delete local logFile
try{
	Remove-Item "$localLogFile" -Force
}
catch{
	Write-Warning "ERROR: Logfile '$localLogFile' could not be deleted.
	Reason: $_"
}
Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 100