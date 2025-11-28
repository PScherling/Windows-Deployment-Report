<#
.SYNOPSIS
    Creates a comprehensive post-deployment system report (HTML + PDF) for a Windows Client, Windows Server and Windows Backup Server and logs all actions.
.DESCRIPTION
    This script inventories the local machine after deployment and generates a human-readable report for build verification and security compliance. It:
	- Initializes logging to C:\_it and \\$SrvIP\Logs$\Custom\Configuration.
	- Collects hardware and OS details (model, manufacturer, serial, CPU(s), RAM, OS name/version/build).
	- Builds an HTML report (with CSS/images copied from \\$SrvIP\DeploymentShare$\Scripts\Custom\DeploymentReport\Media) and saves it to C:\_it\DeploymentReport.
	- Audits OS security configuration: UAC, TLS/SSL protocol states, EnableCertPaddingCheck, LLMNR, WDigest, LSASS PPL, SMBv1/v3, built-in Administrator, “sysadmin” password policy, RDP status & authentication, Location Service, Network Localization, WinRM, SNMP feature.
	- **Backup-server-specific hardening checks:** Windows Script Host, NetBIOS, WinHTTP Auto Proxy Service, WinRM/RemoteRegistry/RDP service states.
	- Checks firewall (RDP/ICMP rules and profile state).
	- Reviews OS adjustments: IPv6 binding, First-Logon Animation, Delayed Desktop Switch, WSUS server & AU settings, OEM info, power plan & power configuration.
	- Gathers storage info: volumes, BitLocker status, VSS configuration.
	- Lists local users & groups, installed software, running default services, and installed drivers/firmware.
	- Converts the HTML to PDF via ConvertToPDF (function/tooling must exist on the system) and finalizes by uploading the log and cleaning up the local log.

.LINK
    https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-computerinfo
	https://learn.microsoft.com/powershell/module/bitlocker/get-bitlockervolume
	https://learn.microsoft.com/windows/security/operating-system-security/network-security/tls/manage-tls
	https://learn.microsoft.com/windows-server/administration/windows-commands/vssadmin
	https://github.com/PScherling

.NOTES
          FileName: custom_create-deployment-report.ps1
          Solution: MDT Deployment Report for Windows Client and Server
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2024-04-26
          Modified: 2025-11-28

          Version - 0.1.0 - () - Finalized functional version 1.
          Version - 0.1.6 - () - Windows 11 Adaption and some minor tweaks
		  Version - 0.1.7 - () - CPU Presentation fixed, if there is more than 1 CPU in the system
		  Version - 0.1.8 - () - Adding Logging Features
		  Version - 0.1.9 - () - Minor Bug fixes regarding design of the report.
		  Version - 0.1.10 - () - Adding new Security Checks.
		  Version - 0.1.11 - () - Reorganizing the report.
		  Version - 0.1.12 - () - Adding Progress Information.
		  Version - 0.1.13 - () - Adapting Information gathering of VSS.
		  Version - 0.1.14 - () - Adding CertPaddingCheck Information.
		  Version - 0.1.15 - () - Adding TLS Cipher Suite Information.
		  Version - 0.2.0 - () - Reorganize the script to make it more accessible for adaptions; merging client report, server report and backup server compliance into one script

          TODO:

.REQUIREMENTS / ASSUMPTIONS
	- Run in an elevated PowerShell session (Administrator).
	- Network access and permissions to \\$SrvIP\DeploymentShare$ and \\$SrvIP\Logs$ shares.
	- PowerShell 5.1+ with CIM/WMI cmdlets available; BitLocker cmdlets where used.
	- A working ConvertToPDF implementation (e.g., wkhtmltopdf/Edge headless) callable by the script.
	- Sufficient disk space in C:\_it and C:\_it\DeploymentReport.

.CONFIGURATION
	- Edit $SrvIP to point to your MDT/Deployment server.
	- Media assets (CSS/images) are expected under \\$SrvIP\DeploymentShare$\Scripts\Custom\DeploymentReport\Media.

.OUTPUT
	- HTML: C:\_it\DeploymentReport\<HOST>_WDSReport_<timestamp>.html
	- PDF:   C:\_it\DeploymentReport\<HOST>_WDSReport_<timestamp>.pdf (after ConvertToPDF)
	- Log:   \\$SrvIP\Logs$\Custom\Configuration\Configure_DeplyomentReport_<HOST>_<timestamp>.log
		
.Example
	Run from an elevated console
	.\custom_create-deployment-report.ps1
#>

Clear-Host
<#
#### Section 1 - Configuration Block | adapt if needed
#>

$Config = @{
	Name 					= "DeplyomentReport"
	Version 				= "0.2.0"
	MDTServerIP 		 	= "0.0.0.0"
	LocalWorkDir         	= "C:\_it"
	CompName 				= $env:COMPUTERNAME
	DateTime 				= Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

	# 1 = enabled; 0 = disabled
	LocalAdminUser 			= "sysadmin"
	ExpectedUACEnabled   	= 1
	ExpectedIPv6        	= 0
	ExpectedLogonAnimation	= 0
	ExpectedDelayedDesktopSwitch = 0
	ExpectedBuiltinAdminEnabled	= 0
	ExpectedAdminPWExpiracy	= 0
	ExpectedRDPStatus		= 1
	ExpectedRDPNetAuth		= 0
	ExpectedLocationSvc		= 0
	ExpectedNetWindow		= 0
	ExpectedWinRM			= 1
	ExpectedSSL2CltV1		= 0
	ExpectedSSL2CltV2		= 1
	ExpectedSSL2SrvV1		= 0
	ExpectedSSL2SrvV2		= 1
	ExpectedSSL3CltV1		= 0
	ExpectedSSL3CltV2		= 1
	ExpectedSSL3SrvV1		= 0
	ExpectedSSL3SrvV2		= 1
	ExpectedTLS1CltV1		= 0
	ExpectedTLS1CltV2		= 1
	ExpectedTLS1SrvV1		= 0
	ExpectedTLS1SrvV2		= 1
	ExpectedTLS11CltV1		= 0
	ExpectedTLS11CltV2		= 1
	ExpectedTLS11SrvV1		= 0
	ExpectedTLS11SrvV2		= 1
	ExpectedTLS12CltV1		= 1
	ExpectedTLS12CltV2		= 0
	ExpectedTLS12SrvV1		= 1
	ExpectedTLS12SrvV2		= 0
	ExpectedTLS13CltV1		= 1
	ExpectedTLS13CltV2		= 0
	ExpectedTLS13SrvV1		= 1
	ExpectedTLS13SrvV2		= 0
	ExpectedLLMNR			= 0
	ExpectedWDigest			= 0
	ExpectedLSASS			= 1
	ExpectedSMBv3			= 1
	ExpectedSMBv1			= 0
	ExpectedCertPadChk		= 1	

	# OEM
	HTMLReportLogo			= "Powershell_logo.png"
	OEMImageFile			= "Powershell_oem.bmp"
	OEMWallpaperFile		= "Wallpaper.jpg"
	
	
	
}



# OEM Paths
$OEMImgBmp				= "C:\windows\system32\$($Config.OEMImageFile)"
$OEMUsrImgBmp			= "C:\ProgramData\Microsoft\User Account Pictures\$($Config.OEMImageFile)"
$OEMGuestImg			= "C:\ProgramData\Microsoft\User Account Pictures\guest.*"
$OEMUsrImg				= "C:\ProgramData\Microsoft\User Account Pictures\user.*"
$OEMUsr32Img			= "C:\ProgramData\Microsoft\User Account Pictures\user-32.png"
$OEMUsr40Img			= "C:\ProgramData\Microsoft\User Account Pictures\user-40.png"
$OEMUsr48Img			= "C:\ProgramData\Microsoft\User Account Pictures\user-48.png"
$OEMUsr192Img			= "C:\ProgramData\Microsoft\User Account Pictures\user-192.png"
$OEMOOBEInfo			= "C:\windows\system32\oobe\info\$($Config.OEMImageFile)"
$OEMOOBEWallpaper		= "C:\windows\system32\oobe\info\backgrounds\$($Config.OEMWallpaperFile)"
$OEMWallpaper			= "C:\Windows\Web\Wallpaper\Windows\$($Config.OEMWallpaperFile)"

# Log an dReport Paths
$LogFileName 			= "Configure_$($Config.Name)_$($Config.CompName)_$($Config.DateTime).log"
$LogFilePath 			= "\\$($Config.MDTServerIP)\Logs$\Custom\Configuration"
$LogFile 				= "$($LogFilePath)\$($LogFileName)"
$LocalLogFile 			= "$($Config.LocalWorkDir)\$($LogFileName)"

$ReportFolder 			= "$($Config.LocalWorkDir)\DeploymentReport"
$MediaFolder 			= "$($ReportFolder)\Media"
$ServerMedia 			= "\\$($Config.MDTServerIP)\DeploymentShare$\Scripts\Custom\DeploymentReport\Media"
$LogShare 				= "\\$($Config.MDTServerIP)\Logs$\Custom\Configuration"



<#
### Section 2 - Helper Functions
#>

# ---------------------------------------------
# Logging
# ---------------------------------------------
function Write-Log {
	param([string]$Message)
	$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	"$timestamp $Message" | Out-File -FilePath "$($LocalLogFile)" -Append
}


# ---------------------------------------------
# Ensure a folder exists
# ---------------------------------------------
function Get-Folder {
	param([string]$Path)
	if (-not (Test-Path $Path)) {
		try {
			New-Item -Path $Path -ItemType Directory -Force | Out-Null
			Write-Log "Created directory: $Path"
		}
		catch {
			Write-Log "ERROR: Failed to create directory: $Path - $_"
		}
	}
	else {
		Write-Log "Directory already exists: $Path"
	}
}



# ---------------------------------------------
# Begin a report section (console + log)
# ---------------------------------------------
function Start-Section {
	param([string]$Name)
	Write-Host "########################################"
	Write-Host "# $Name"
	Write-Host "########################################`n"
	Write-Log "Starting section: $Name"
}

# ---------------------------------------------
# Add an HTML block to the report file
# ---------------------------------------------
function Add-HtmlBlock {
	param([string]$Html)
	Add-Content -Path $global:HTMLFilePath -Value $Html
}


# ---------------------------------------------
# Add a simple two-column table row
# ---------------------------------------------
<#
function Add-TableRow {
	param(
		[string]$Name,
		[string]$Value
	)


	Add-HtmlBlock "<tr><td>$Name</td><td>$Value</td></tr>"
}
#>

# ---------------------------------------------
# Convert HTML - PDF using Edge Chromium
# ---------------------------------------------
function Convert-ToPDF {
	param([string]$HtmlFile)


	$PdfFile = [IO.Path]::ChangeExtension($HtmlFile, ".pdf")
	Write-Log "Converting to PDF: $PdfFile"

	Start-Sleep 5
	try {

		Start-Process "msedge.exe" -ArgumentList @("--headless","--print-to-pdf=""$PdfFile""","--disable-extensions","--no-pdf-header-footer","--disable-popup-blocking","--run-all-compositor-stages-before-draw","--disable-checker-imaging", "file:///$HtmlFile")
		
	}
	catch {
		Write-Log "ERROR: PDF conversion failed: $_"
	}
	Start-Sleep 5
}


# ---------------------------------------------
# Cleanup and variable reset
# ---------------------------------------------
function Flush-Variables {
	Start-Sleep 5
	Write-Log "Flushing variables from memory."
	Get-Variable -Scope Script | Where-Object { $_.Name -notin 'Config' } | Remove-Variable -Force -ErrorAction SilentlyContinue
}


<#
### Section 3 - Data Collection Functions (Get-*)
#>

# ---------------------------------------------------------
# System Information
# ---------------------------------------------------------
function Get-SystemInfo {
	# System Info
	$SysModel = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Model
	$SysName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Name
	$SysManufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Manufacturer
	$SysType = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property SystemType
	$SN = (Get-WmiObject -class win32_bios).SerialNumber

	# OS Info
	$OSInfo = Get-ComputerInfo | select OSName,OSDisplayVersion,WindowsVersion,OSVersion #select WindowsProductName,WindowsVersion,OsVersion
	$OSDisplayVersion = $OSInfo.OSDisplayVersion
	if([string]::IsNullOrEmpty($global:OSDisplayVersion) -and $global:OSVersion -eq "10.0.19044" -and $global:WindowsVersion -eq "2009") 
	{ 
		$OSDisplayVersion = "21H2" 
	}

	# CPU Info
	$CPUInfos = Get-WmiObject -class win32_processor -Property name,numberOfCores,NumberOfLogicalProcessors | Select-Object -Property name,numberOfCores,NumberOfLogicalProcessors

	# RAM Info
	#Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
	#(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
	$RAMInfo = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}


	return [PSCustomObject]@{
		Hostname 			= $SysName.Name
		Manufacturer 		= $SysManufacturer.Manufacturer
		Model 				= $SysModel.Model
		SerialNumber 		= $SN
		SystemType 			= $SysType.SystemType

		WindowsProduct 		= $OSInfo.OSName #$OSInfo.WindowsProductName
		WindowsVersion 		= $OSInfo.WindowsVersion
		OSVersion 			= $OSInfo.OSVersion
		OSDisplayVersion 	= $OSDisplayVersion

		CPUName 			= $CPUInfos.name
		CPUCores 			= $CPUInfos.numberOfCores
		CPULogProc 			= $CPUInfos.NumberOfLogicalProcessors
		CPUCount 			= $CPUInfos.Count
		RAMInfo 			= $RAMInfo

	}
}


# ---------------------------------------------------------
# UAC Status
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		UACStatus 			= $UACStatus
	}

   
}


# ---------------------------------------------------------
# IPv6 Status
# ---------------------------------------------------------
function Get-IPv6Status {
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

	return [PSCustomObject]@{
		AdapterName 			= $AdapterName
		IPv6Setting				= $IPv6Setting.Enabled
	}
}


# ---------------------------------------------------------
# Hide Shell Cleanup Status | First Logon Animation
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		AnimationStatus 			= $AnimationStatus
	}
}

# ---------------------------------------------------------
# Delayed Desktop Switch Timeout Status
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		DesktopSwitchStatus 			= $DesktopSwitchStatus
	}
}


# ---------------------------------------------------------
# Builtin Local Administrator Status
# ---------------------------------------------------------
function Get-BuiltinAdminStatus {
	try {
		$BuiltinAdmin = Get-LocalUser -Name "Administrator" | select Enabled
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch information for default administrator user account."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch information for default administrator user account.
$_"
	}

	return [PSCustomObject]@{
		BuiltinAdminStatus 			= $BuiltinAdmin.Enabled
	}
}


# ---------------------------------------------------------
# Local Administrator User Password Expiracy Status
# ---------------------------------------------------------
function Get-LocalAdminPWStatus {
	try {
		$LocalUser = Get-LocalUser -Name "$($Config.LocalAdminUser)"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch user account information for '$($Config.LocalAdminUser)'."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch user account information for '$($Config.LocalAdminUser)'.
$_"
	}
	
	if($LocalUser) {
		try {
			$PWExpireStatus = Get-LocalUser -Name $($Config.LocalAdminUser) | select PasswordExpires
		}
		catch {
			Write-Warning "Something went wrong. Could not fetch password expiracy setting for user account '$($Config.LocalAdminUser)'."
			Write-Warning " Error Message: $_"
			Write-Log "ERROR: Something went wrong. Could not fetch password expiracy setting for user account '$($Config.LocalAdminUser)'.
	$_"
		}

		return [PSCustomObject]@{
			LocalAdminPWStatus 			= if($PWExpireStatus) { $PWExpireStatus.PasswordExpires} else {@()}
		}
	}
}


# ---------------------------------------------------------
# RDP Status
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		RDPStatus 			= $RDPStatus.fDenyTSConnections
	}
}

# ---------------------------------------------------------
# RDP Authentication Status
# ---------------------------------------------------------
function Get-RDPAuth {
	try {
		$RDPAuth = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"  | select UserAuthentication
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch RDP Authentication settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch RDP Authentication settings.
$_"
	}

	return [PSCustomObject]@{
		RDPNetAuth			= $RDPAuth.UserAuthentication
	}
}

# ---------------------------------------------------------
# Location Service Status
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		LocationSvcStatus			= $LocationServiceStatus.Value
	}
}

# ---------------------------------------------------------
# Network Window Status
# ---------------------------------------------------------
function Get-NetworkLocalization {
	try {	
        $NetworkLocalisation = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch 'Network Localization' information settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch 'Network Localization' information settings"
	}

	return [PSCustomObject]@{
		NetLocalStatus			= if($NetworkLocalisation) { $NetworkLocalisation } else { @() }
	}
}


# ---------------------------------------------------------
# WinRM Status
# ---------------------------------------------------------
function Get-WinRMStatus {
	try {
		$WinRMSvc = Get-Service -Name "WinRM" | select Status,Name,DisplayName
		$i = 0
		while ($($WinRMSvc.Status) -ne 'Running' -and $i -lt 30) {
			Write-Log "Waiting for '$($WinRMSvc.Name)' to start..."
			Start-Sleep -Seconds 5
			$i = $i + 5
			$WinRMSvc = Get-Service -Name "WinRM" | select Status,Name,DisplayName
			Write-Log "'$($WinRMSvc.Name)' status: $($WinRMSvc.Status)"
		}
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WinRM service information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WinRM service information.
$_"
	}

	return [PSCustomObject]@{
		WinRMStatus			= $WinRMSvc.Status
		WinRMName           = $WinRMSvc.Name
		WinRMDisplayName	= $WinRMSvc.DisplayName
	}
}


# ---------------------------------------------------------
# SNMP Feature Status
# ---------------------------------------------------------
function Get-SNMPFeature {
	try {
		$SNMPFeature = Get-WindowsCapability -Online -Name "SNMP*" | select State,DisplayName,Description
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch SNMP FoD information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch SNMP FoD information.
$_"
	}

	return [PSCustomObject]@{
		SNMPFeature			= $SNMPFeature
	}
}

# ---------------------------------------------------------
# VSS Status
# ---------------------------------------------------------
function Get-VSSStatus {
	function Get-Cfg {
		try{
			$volumes = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }  # DriveType 3 means Local Disk
		}
		catch{
			Write-Log "ERROR: Can not fetch volume information. Reason: $_"
			Exit
		}

		$results = @()

		foreach ($volume in $volumes) {
			$driveLetter = $volume.DeviceID
			#Write-Log "Get VSS Limit for volume '$($driveLetter)'"
			#Write-Log "Fetch current shadow storage settings for the drive."
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
				#Write-Log "Maximum VSS Setting for Volume '$($driveLetter)': $MaxVSS"
				
			} else {
				#Write-Log "No shadow storage found for volume '$($driveLetter)'."
				$MaxVSS = "-"
				
			}

			# add structured entry
			$results += [pscustomobject]@{
				DriveLetter  	= $driveLetter
				MaxVSS  		= $MaxVSS
			}
		}

		return $results
	}

	$VSSConfig = Get-Cfg

	return [PSCustomObject]@{
		VSSConfig			= $VSSConfig
	}


}


# ---------------------------------------------------------
# RDP Firewall Status
# ---------------------------------------------------------
function Get-RDPFirewall {
	try {
		$RDPFWRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | select DisplayName,DisplayGroup,Description,Enabled
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch firewall settings for RDP."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch firewall settings for RDP.
$_"
	}

	

	return [PSCustomObject]@{
		RDPFWRules			= if ($RDPFWRules) { $RDPFWRules } else { @() }
	}
}

# ---------------------------------------------------------
# ICMP Firewall Status
# ---------------------------------------------------------
function Get-ICMPFirewall {
	try {
		$ICMPAllowed = Get-NetFirewallRule -DisplayName "ICMP Allow incoming V4 echo request" | select DisplayName,Name,Enabled,Profile
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch firewall settings for ICMP."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch firewall settings for ICMP.
$_"
	}

	return [PSCustomObject]@{
		ICMPAllowed			= if ($ICMPAllowed) { $ICMPAllowed } else { @() }
	}
}

# ---------------------------------------------------------
# Windows Firewall Status
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		FirewallProfiles		= if ($FirewallProfiles) { $FirewallProfiles } else { @() }
	}
}


# ---------------------------------------------------------
# WSUS Settings
# ---------------------------------------------------------
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

	return [PSCustomObject]@{
		WSUSInfo		= if ($GetWSUSInfo) { $GetWSUSInfo } else { @() }
	}
}

# ---------------------------------------------------------
# WSUS Options Status
# ---------------------------------------------------------
function Get-WSUSOptions {
	try {
		$GetWSUSOptions = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | select AUOptions,UseWUServer,NoAutoRebootWithLoggedOnUsers,NoAutoUpdate,ScheduledInstallDay,ScheduledInstallTime
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WSUS settings."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WSUS settings.
$_"
	}

	return [PSCustomObject]@{
		WSUSOptions		= if ($GetWSUSOptions) { $GetWSUSOptions } else { @() }
	}
}


# ---------------------------------------------------------
# OEM Info
# ---------------------------------------------------------
function Get-OEMInfo {
	try{
		$OEMValues = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation" | select Manufacturer,Logo
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch OEM information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch OEM information.
$_"
	}

	
	if(test-path "$($OEMImgBmp)") {
		#Write-Log "OEM Image file '$($Config.OEMImageFile)' is available in 'C:\windows\system32\'."
		$OEMImgBmpValue = 1
    }
    else {
		#Write-Log "OEM Image file '$($Config.OEMImageFile)' is not available in 'C:\windows\system32\'."
		$OEMImgBmpValue = 0
    }

	if(test-path "$($OEMUsrImgBmp)") {
		#Write-Log "OEM User Account Image is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsrImgBmpValue = 1
    }
    else {
		#Write-Log "OEM User Account Image is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsrImgBmpValue = 0
    }

	if(test-path "$($OEMGuestImg)") {
		#Write-Log "Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMGuestImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMGuestImgValue = 0
    }

	if(test-path "$($OEMUsrImg)") {
		#Write-Log "Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsrImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsrImgValue = 0
    }

	if(test-path "$($OEMUsr32Img)") {
		#Write-Log "Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr32ImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr32ImgValue = 0
    }

	if(test-path "$($OEMUsr40Img)") {
		#Write-Log "Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr40ImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr40ImgValue = 0
    }

	if(test-path "$($OEMUsr48Img)") {
		#Write-Log "Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr48ImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr48ImgValue = 0
    }

	if(test-path "$($OEMUsr192Img)") {
		#Write-Log "Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr192ImgValue = 1
    }
    else {
		#Write-Log "Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		$OEMUsr192ImgValue = 0
    }

	if(test-path "$($OEMOOBEInfo)") {
		#Write-Log "OEM Image '$($Config.OEMImageFile)' is available in 'C:\windows\system32\oobe\info\'."
		$OEMOOBEInfoValue = 1
    }
    else {
		#Write-Log "OEM Image '$($Config.OEMImageFile)' is not available in 'C:\windows\system32\oobe\info\'."
		$OEMOOBEInfoValue = 0
    }


	if(test-path "$($OEMOOBEWallpaper)") {
		#Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\windows\system32\oobe\info\backgrounds\'."
		$OEMOOBEWallpaperValue = 1
    }
    else {
		#Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in C:\windows\system32\oobe\info\backgrounds\'."
		$OEMOOBEWallpaperValue = 0
    }
    if(test-path "$($OEMWallpaper)") {
		#Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\Windows\Web\Wallpaper\Windows\'."
		$OEMWallpaperValue = 1
    }
    else {
		#Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in 'C:\Windows\Web\Wallpaper\Windows\'."
		$OEMWallpaperValue = 0
    }

	return [PSCustomObject]@{
		OEMValues				= $OEMValues
		OEMImgBmpValue			= $OEMImgBmpValue
		OEMUsrImgBmpValue		= $OEMUsrImgBmpValue
		OEMGuestImgValue		= $OEMGuestImgValue
		OEMUsrImgValue			= $OEMUsrImgValue
		OEMUsr32ImgValue		= $OEMUsr32ImgValue
		OEMUsr40ImgValue		= $OEMUsr40ImgValue
		OEMUsr48ImgValue		= $OEMUsr48ImgValue
		OEMUsr192ImgValue		= $OEMUsr192ImgValue
		OEMOOBEInfoValue		= $OEMOOBEInfoValue
		OEMOOBEWallpaperValue	= $OEMOOBEWallpaperValue
		OEMWallpaperValue		= $OEMWallpaperValue
	}

}


# ---------------------------------------------------------
# PowerPlan Status
# ---------------------------------------------------------
function Get-PowerPlan {
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
	
	#Write-Log "PowerPlan Settings"
	#Write-Log "Name:                $PPlanName"
	#Write-Log "Description:         $PPlanDesc"
	#Write-Log "Status Enabled:      $PPlanActive"

	return [PSCustomObject]@{
		PPlanName			= $PPlanName
		PPlanDesc 			= $PPlanDesc 
		PPlanActive 		= $PPlanActive
	}
}

# ---------------------------------------------------------
# PowerPlan Config
# ---------------------------------------------------------
function Get-PowerPlanConfig {
	function Get-Cfg {
		[CmdletBinding()]
		param(
			[string] $Scheme,
			[switch] $Raw
		)

		$results = @()
		
		# same GUID -> Name mapping
		$settingGuidsToNames = [ordered] @{
			'3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' = 'Monitor Timeout'
			'6738e2c4-e8a5-4a42-b16a-e040e769756e' = 'Disk Timeout'
			'29f6c1db-86da-48c5-9fdb-f2b67b1f44da' = 'Standby Timeout'
			'9d7815a6-7ee4-497e-8888-515a05f02364' = 'Hibernate Timeout'
			'48e6b7a6-50f5-4782-a5d4-53bb8f07e226' = 'USB Selective Suspend'
		}

		# collect schemes
		$allSchemes = 
			@(powercfg.exe -list) -ne '' |
			Select-Object -Skip 2 |
			ForEach-Object { 
				$null, $guid, $name, $other = ($_ -split '[:()]').Trim()
				[pscustomobject] @{
					Name = $name
					Guid = $guid
					Active = [bool] $other
				}
			}

		if (-not $Scheme) {
			$matchingSchemes = $allSchemes | Where-Object Active
		}
		elseif ($Scheme -as [guid]) {
			$matchingSchemes = $allSchemes | Where-Object { $_.Guid -eq $Scheme }
		}
		else {
			$matchingSchemes = $allSchemes | Where-Object { $_.Name -like $Scheme }
		}

		if (-not $matchingSchemes) { throw "No matching scheme '$Scheme' found." }

		foreach ($matchingScheme in $matchingSchemes) {

			$allSettingsText = powercfg.exe -query $matchingScheme.Guid
			if ($Raw) { return $allSettingsText }

			$paragraphs = ($allSettingsText -join "`n") -split '\n{2}' -match '\S'

			foreach ($kv in $settingGuidsToNames.GetEnumerator()) {

				$guid = $kv.Key
				$settingName = $kv.Value

				$lines = $paragraphs.Where({ $_ -match $guid }, 'First')[0] -split '\n'
				[uint32]$acValue, [uint32]$dcValue = $lines[-2, -1] -replace '^.+: '

				if ($guid -ne '48e6b7a6-50f5-4782-a5d4-53bb8f07e226') {
					# normal settings -> minutes
					$ac = if ($acValue -eq 0) { "Deactivated" } else { "$($acValue/60) Minutes" }
					$dc = if ($dcValue -eq 0) { "Deactivated" } else { "$($dcValue/60) Minutes" }
				}
				else {
					# USB SS -> enabled/disabled
					$ac = if($acValue -eq 0) { "Deactivated" } else { "Activated" }
					$dc = if($dcValue -eq 0) { "Deactivated" } else { "Activated" }
				}

				# add structured entry
				$results += [pscustomobject]@{
					Setting  = $settingName
					ACValue  = $ac
					DCValue  = $dc
				}
			}
		}

		return $results
	}

	$PowerConfig = Get-Cfg

	return [PSCustomObject]@{
		PowerConfig			= $PowerConfig
	}
}


# ---------------------------------------------------------
# Installed Software Status
# ---------------------------------------------------------
function Get-InstalledSoftware {
	$ErrorActionPreference = "SilentlyContinue"
	
	try {
		#$ErrorActionPreference = "SilentlyContinue"
		$GetSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | where-object { $_.DisplayName -ne $null -and $_.DisplayVersion -ne $null -and $_.Publisher -ne $null } | Sort-Object -Property DisplayName, DisplayVersion, Publisher #| Format-Table
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch all information for installed software."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch all information for installed software.
$_"
	}
	
	#Set back to default value 'Continue'
	$ErrorActionPreference = "Continue"


	return [PSCustomObject]@{
		Software			= $GetSoftware
	}
}


# ---------------------------------------------------------
# Default Running Services Status
# ---------------------------------------------------------
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


	return [PSCustomObject]@{
		Services			= $GetSvc
	}
}

# ---------------------------------------------------------
# Installed Driver and Firmware Status
# ---------------------------------------------------------
function Get-InstalledDrivers {
	try {
		$SignedDrivers = Get-WmiObject Win32_PnPSignedDriver | select DeviceName, Manufacturer, DriverVersion | where-object { $_.DeviceName -ne $null -and $_.Manufacturer -ne $null -and $_.DriverVersion -ne $null } | Sort-Object -Property DeviceName, Manufacturer, DriverVersion
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any signed and installed driver."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any signed and installed drive.
$_"
	}

	return [PSCustomObject]@{
		SignedDrivers			= $SignedDrivers
	}
}

# ---------------------------------------------------------
# Volume Information Status
# ---------------------------------------------------------
function Get-VolumeInfo {
	try {
		$Volumes = Get-Volume
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any volume information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any volume information.
$_"
	}

	return [PSCustomObject]@{
		Volumes			= $Volumes
	}
}

# ---------------------------------------------------------
# BitLocker Status
# ---------------------------------------------------------
function Get-BitLockerInfo {
	try {
		$Volumes = get-bitlockervolume | select VolumeType,MountPoint,KeyProtector,ProtectionStatus
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch BitLocker information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch BitLocker information.
$_"
	}

	return [PSCustomObject]@{
		Volumes			= $Volumes
	}
}

# ---------------------------------------------------------
# Local User Information Status
# ---------------------------------------------------------
function Get-LocalUserInfo {
	try {
		$Users = get-localuser
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any local user account information."
		Write-Warning " Error Message: $_"
		Write-Log "Something went wrong. Could not fetch any local user account information.
$_"
	}

	return [PSCustomObject]@{
		LocalUsers			= $Users
	}

}

# ---------------------------------------------------------
# Local Group Information Status
# ---------------------------------------------------------
function Get-LocalGroupsInfo {
	try {
		$Groups = get-localgroup
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any local user group information."
		Write-Warning " Error Message: $_"		
		Write-Log "Something went wrong. Could not fetch any local user group information.
$_"
	}

	return [PSCustomObject]@{
		LocalGroups			= $Groups
	}
}

# ---------------------------------------------------------
# TLS Status
# ---------------------------------------------------------
function Get-TLSStatus {

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
		Write-Log "ERROR: Something went wrong. Could not fetch SSL 2.0 information: $_"
	}

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
		Write-Log "ERROR: Something went wrong. Could not fetch SSL 3.0 information: $_"
	}

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
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.0 information: $_"
	}

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
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.1 information: $_"
	}

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
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.2 information: $_"
	}

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
		Write-Log "ERROR: Something went wrong. Could not fetch TLS 1.3 information: $_"
	}


	return [PSCustomObject]@{
		SSL2ClientValue1 			= $ssl2ClientValue1.Enabled
		SSL2ClientValue2 			= $ssl2ClientValue2.DisabledByDefault
		SSL2ServerValue1			= $ssl2ServerValue1.Enabled
		SSL2ServerValue2			= $ssl2ServerValue2.DisabledByDefault
		SSL3ClientValue1			= $ssl3ClientValue1.Enabled
		SSL3ClientValue2			= $ssl3ClientValue2.DisabledByDefault
		SSL3ServerValue1			= $ssl3ServerValue1.Enabled
		SSL3ServerValue2			= $ssl3ServerValue2.DisabledByDefault
		TLS1ClientValue1			= $tls1ClientValue1.Enabled
		TLS1ClientValue2			= $tls1ClientValue2.DisabledByDefault
		TLS1ServerValue1			= $tls1ServerValue1.Enabled
		TLS1ServerValue2			= $tls1ServerValue2.DisabledByDefault
		TLS1_1ClientValue1			= $tls1_1ClientValue1.Enabled
		TLS1_1ClientValue2			= $tls1_1ClientValue2.DisabledByDefault
		TLS1_1ServerValue1			= $tls1_1ServerValue1.Enabled
		TLS1_1ServerValue2			= $tls1_1ServerValue2.DisabledByDefault
		TLS1_2ClientValue1			= $tls1_2ClientValue1.Enabled
		TLS1_2ClientValue2			= $tls1_2ClientValue2.DisabledByDefault
		TLS1_2ServerValue1			= $tls1_2ServerValue1.Enabled
		TLS1_2ServerValue2			= $tls1_2ServerValue2.DisabledByDefault
		TLS1_3ClientValue1			= $tls1_3ClientValue1.Enabled
		TLS1_3ClientValue2			= $tls1_3ClientValue2.DisabledByDefault
		TLS1_3ServerValue1			= $tls1_3ServerValue1.Enabled
		TLS1_3ServerValue2			= $tls1_3ServerValue2.DisabledByDefault

	}
}

# ---------------------------------------------------------
# LLMNR Status
# ---------------------------------------------------------
function Get-LLMNR {
	$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

	try {
		$LLMNRValue = Get-ItemProperty -Path "$($RegPath)" -Name "EnableMulticast"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Link-Local Multicast Resolution (LLMNR) information.
$_"
	}

	return [PSCustomObject]@{
		LLMNRStatus			= $LLMNRValue.EnableMulticast
	}
}

# ---------------------------------------------------------
# WDigest Status
# ---------------------------------------------------------
function Get-WDigest {
	$RegPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"

	try {
		$WDigestValue = Get-ItemProperty -Path "$($regPath)" -Name "UseLogonCredential"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WDigest Credential Caching information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WDigest Credential Caching information.
$_"
	}

	return [PSCustomObject]@{
		WDigestStatus			= $WDigestValue.UseLogonCredential
	}
}

# ---------------------------------------------------------
# LSASS Status
# ---------------------------------------------------------
function Get-LSASSStatus {
	$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

	try {
		$LSASSValue = Get-ItemProperty -Path "$($regPath)" -Name "RunAsPPL"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch LSASS information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch LSASS information.
$_"
	}

	return [PSCustomObject]@{
		LSASSStatus			= $LSASSValue.RunAsPPL
	}
}

# ---------------------------------------------------------
# SMBv3 Status
# ---------------------------------------------------------
function Get-SMB3 {
	
	try{
		$CurrentSignature = Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Signature information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Signature information.
$_"
	}
	
	try{
		$CurrentEncryption = Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Encryption information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Encryption information.
$_"
	}
	
	try{
		$CurrentSecurity = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch SMBv3 Security information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv3 Security information.
$_"
	}

	return [PSCustomObject]@{
		SMB3Signature			= $CurrentSignature
		SMB3Encryption			= $CurrentEncryption
		SMB3Security			= $CurrentSecurity
	}
}

# ---------------------------------------------------------
# SMBv1 Status
# ---------------------------------------------------------
function Get-SMB1 {
	
	try {
		$SMB1Status = Get-WindowsOptionalFeature -Online -FeatureName "*SMB1Protocol*"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch SMBv1 information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch SMBv1 information.
$_"
	}

	return [PSCustomObject]@{
		SMB1Status			= $SMB1Status
	}
}

# ---------------------------------------------------------
# Cert Padding Check Status
# ---------------------------------------------------------
function Get-CertPaddingCheck {
	
	$RegPath1 = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config\"
	$RegPath2 = "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\"
	
	
	try {
		$PaddingRegValue1 = Get-ItemProperty -Path "$($RegPath1)" -Name "EnableCertPaddingCheck"
		$PaddingRegValue2 = Get-ItemProperty -Path "$($RegPath2)" -Name "EnableCertPaddingCheck"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch CertPaddingCheck information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch CertPaddingCheck information.
$_"
	} 
	
	return [PSCustomObject]@{
		PaddingRegValue1			= $PaddingRegValue1.EnableCertPaddingCheck
		PaddingRegValue2 			= $PaddingRegValue2.EnableCertPaddingCheck
	}
	
}

# ---------------------------------------------------------
# TLS Cipher Suites Check Status
# ---------------------------------------------------------
function Get-TLSCipherSuites {

	try {
		# Get all current cipher suites
		$GetCiphers = Get-TlsCipherSuite
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch TLS Cipher Suites information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch TLS Cipher Suites information.
$_"
	}

	return [PSCustomObject]@{
		Ciphers			= if ($GetCiphers) { $GetCiphers.Name } else { @() }
	}
}

# ---------------------------------------------------------
# Windows Server Roles and Features Status
# ---------------------------------------------------------
function Get-InstalledRolesFeatures {
	try{
		$RolesFeatures = Get-WindowsFeature | select Name, InstallState | where-object {$_.InstallState -eq "Installed"} | Sort-Object -Property Name, InstallState
	}
	catch{
		
		Write-Warning "Something went wrong. Could not fetch any installed Roles or Features."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch all information for Roles and Features.
$_"
	}

	
	return [PSCustomObject]@{
		RolesFeatures		= if ($RolesFeatures) { $RolesFeatures } else { @() }
	}
}



<# ---------------------------------------------------------
### BACKUP SERVER SECURITY COMPLIANCE
#>

# ---------------------------------------------------------
# Windows Script Host Status
# ---------------------------------------------------------
function Get-WinScriptHost {
	try {
		$regPath = "HKLM:\Software\Microsoft\Windows Script Host\Settings"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Windows Script Host information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Windows Script Host information.
$_"
	}

	try {
		$regValue = Get-ItemProperty -Path "$($regPath)" -Name "Enabled" -ErrorAction SilentlyContinue
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch Windows Script Host information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch Windows Script Host information.
$_"
	}

	return [PSCustomObject]@{
		WinScriptState			= $regValue
	}
}

# ---------------------------------------------------------
# NetBIOS Status
# ---------------------------------------------------------
function Get-NetBios {
	try{
		$interfaces = Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | Select -ExpandProperty PSChildName
	}
	catch{
		Write-Warning "Something went wrong. Could not fetch network interface information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch network interface information.
$_"
	}
	
	return [PSCustomObject]@{
		NetBiosState			= $interfaces
	}
}


# ---------------------------------------------------------
# Windows HTTP Auto Proxy Status
# ---------------------------------------------------------
function Get-WinHttpAutoProxy {
	try {
		$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WinHttpAutoProxy information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WinHttpAutoProxy information.
$_"
	}
	
	try {
		$regValue = Get-ItemProperty -Path "$($regPath)" -Name "Start"
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WinHttpAutoProxy information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WinHttpAutoProxy information.
$_"
	}

	return [PSCustomObject]@{
		WinHttpAutoProxyState			= $regValue
	}

}

# ---------------------------------------------------------
# WinRM Service Status
# ---------------------------------------------------------
function Get-WinRMSvcStatus {
	try {
		$WinRMSvc = Get-Service -Name "WinRM" | select Status,Name,DisplayName,StartType
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch WinRM service information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch WinRM service information.
$_"
	}

	return [PSCustomObject]@{
		WinRMInfo			= $WinRMSvc
	}
}


# ---------------------------------------------------------
# Remote Registry Status
# ---------------------------------------------------------
function Get-RemoteRegistry {
	try {
		$RemoteRegistrySvc = Get-Service -Name "RemoteRegistry" | select Status,Name,DisplayName,StartType
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch RemoteRegistry service information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch RemoteRegistry service information.
$_"
	}

	return [PSCustomObject]@{
		RemoteRegistryInfo			= $RemoteRegistrySvc
	}

}

# ---------------------------------------------------------
# Remote Desktop Service Status
# ---------------------------------------------------------
function Get-TermSvcStatus {

	try {
		$TermSvc = Get-Service -Name "TermService" | select Status,Name,DisplayName,StartType
	}
	catch {
		Write-Warning "Something went wrong. Could not fetch RDP service information."
		Write-Warning " Error Message: $_"
		Write-Log "ERROR: Something went wrong. Could not fetch RDP service information.
$_"
	}

	return [PSCustomObject]@{
		TermSvcInfo			= $TermSvc
	}

}



# ---------------------------------------------------------



<#
### Section 4 - HTML Builder Functions (Write-*)
#>

# ---------------------------------------------------------
# Write System Information
# ---------------------------------------------------------
function Write-SystemInfoHtml {
	param($Data)

	Write-Log "Hostname: $($Data.Hostname)"
	Write-Log "System Type: $($Data.SystemType)"
	Write-Log "Manufacturer: $($Data.Manufacturer)"
	Write-Log "Model: $($Data.Model)"
	Write-Log "Serial Number: $($Data.SerialNumber)"
	
	Add-HtmlBlock @"
<h2>System Information</h2>
<table><tbody>
<tr><td>Hostname:</td><td>$($Data.Hostname)</td></tr> 
<tr><td>System Type:</td><td>$($Data.SystemType)</td></tr>
<tr><td>Manufacturer:</td><td>$($Data.Manufacturer)</td></tr>
<tr><td>Model:</td><td>$($Data.Model)</td></tr>
<tr><td>Serial Number:</td><td>$($Data.SerialNumber)</td></tr>
"@


	# CPU section (supports multi-CPU)
	if ($Data.CPUCount -gt 1) {
		for ($i = 0; $i -lt $Data.CPUCount; $i++) {
			Write-Log "--- CPU $i ---"
			Write-Log "CPU: $($Data.CPU[$i].CPUName)"
			Write-Log "CPU Cores: $($Data.CPU[$i].CPUCores)"
			Write-Log "Logical Procs: $($Data.CPU[$i].CPULogProc)"
			Add-HtmlBlock "<tr><td>CPU $i</td><td><table class='nested'>"
			Add-HtmlBlock "<tr><td>CPU:</td><td>$($Data.CPU[$i].CPUName)</td></tr>"
			Add-HtmlBlock "<tr><td>CPU Cores:</td><td>$($Data.CPU[$i].CPUCores)</td></tr>"
			Add-HtmlBlock "<tr><td>Logical Procs:</td><td>$($Data.CPU[$i].CPULogProc)</td></tr>"
			Add-HtmlBlock "</table></td></tr>"
		}
	}
	else {
		Write-Log "--- CPU 0 ---"
		Write-Log "CPU: $($Data.CPUName)"
		Write-Log "CPU Cores: $($Data.CPUCores)"
		Write-Log "Logical Procs: $($Data.CPULogProc)"
		Add-HtmlBlock "<tr><td>CPU 0</td><td><table class='nested'>"
		Add-HtmlBlock "<tr><td>CPU:</td><td>$($Data.CPUName)</td></tr>"
		Add-HtmlBlock "<tr><td>CPU Cores:</td><td>$($Data.CPUCores)</td></tr>"
		Add-HtmlBlock "<tr><td>Logical Procs:</td><td>$($Data.CPULogProc)</td></tr>"
		Add-HtmlBlock "</table></td></tr>"
	}

	Write-Log "RAM: $($Data.RAMInfo) GB"
	Write-Log "OS: $($Data.WindowsProduct)"
	Write-Log "OS Version: $($Data.OSDisplayVersion)"
	Write-Log "OS Build: $($Data.OSVersion)"
	Write-Log "OS ReleaseID: $($Data.WindowsVersion)"
	Add-HtmlBlock @"
<tr><td>RAM:</td><td>$($Data.RAMInfo) GB</td></tr>
<tr><td>OS:</td><td>$($Data.WindowsProduct)</td></tr>
<tr><td>OS Version:</td><td>$($Data.OSDisplayVersion)</td></tr>
<tr><td>OS Build:</td><td>$($Data.OSVersion)</td></tr>
<tr><td>OS ReleaseID:</td><td>$($Data.WindowsVersion)</td></tr>
</tbody></table>
"@
}

# ---------------------------------------------------------
# Write UAC Information
# ---------------------------------------------------------
function Write-UACHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>User Account Control</h3>
	<table>
	<tbody>
"@
    if ($($Data.UACStatus) -eq $($Config.ExpectedUACEnabled)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>UAC is enabled. &#9989</td>
        </tr>
"@

       
		Write-Log "UAC is enabled."
        
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>UAC is disabled. &#10060</td>
        </tr>
"@
        
		Write-Log "ERROR: UAC is disabled."
        
    }
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write TLS Information
# ---------------------------------------------------------
function Write-TLSHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>SSL/TLS Configuration</h3>
	<table>
	<tbody>
"@


	Add-HtmlBlock @"
	<h4>SSL 2.0 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.SSL2ClientValue1) -ne $($Config.ExpectedSSL2CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client not disabled. &#10060</td>
        </tr>
"@

       Write-Log "SSL 2.0 Client is not disabled."
        
    }
    elseif ($($Data.SSL2ClientValue1) -eq $($Config.ExpectedSSL2CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is disabled. &#9989</td>
        </tr>
"@
        Write-Log "SSL 2.0 Client is disabled."
        
    }

	if ($($Data.SSL2ClientValue2) -ne $($Config.ExpectedSSL2CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "SSL 2.0 Client is not disabled by default."
        
    }
    elseif ($($Data.SSL2ClientValue2) -eq $($Config.ExpectedSSL2CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Client is disabled by default. &#9989</td>
"@
        Write-Log "SSL 2.0 Client is disabled by default."
        
    }


	if ($($Data.SSL2ServerValue1) -ne $($Config.ExpectedSSL2SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server not disabled. &#10060</td>
        </tr>
"@

       Write-Log "SSL 2.0 Server is not disabled."
        
    }
    elseif ($($Data.SSL2ServerValue1) -eq $($Config.ExpectedSSL2SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is disabled. &#9989</td>
        </tr>
"@
        Write-Log "SSL 2.0 Server is disabled."
        
    }

	if ($($Data.SSL2ServerValue2) -ne $($Config.ExpectedSSL2SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "SSL 2.0 Server is not disabled by default."
        
    }
    elseif ($($Data.SSL2ServerValue2) -eq $($Config.ExpectedSSL2SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 2.0 Server is disabled by default. &#9989</td>
"@
        Write-Log "SSL 2.0 Server is disabled by default."
        
    }
	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@
	

	Add-HtmlBlock @"
	<h4>SSL 3.0 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.SSL3ClientValue1) -ne $($Config.ExpectedSSL3CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client not disabled. &#10060</td>
        </tr>
"@

       Write-Log "SSL 3.0 Client is not disabled."
        
    }
    elseif ($($Data.SSL3ClientValue1) -eq $($Config.ExpectedSSL3CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is disabled. &#9989</td>
        </tr>
"@
        Write-Log "SSL 3.0 Client is disabled."
        
    }

	if ($($Data.SSL3ClientValue2) -ne $($Config.ExpectedSSL3CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "SSL 3.0 Client is not disabled by default."
        
    }
    elseif ($($Data.SSL3ClientValue2) -eq $($Config.ExpectedSSL3CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Client is disabled by default. &#9989</td>
"@
        Write-Log "SSL 3.0 Client is disabled by default."
        
    }


	if ($($Data.SSL3ServerValue1) -ne $($Config.ExpectedSSL3SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server not disabled. &#10060</td>
        </tr>
"@

       Write-Log "SSL 3.0 Server is not disabled."
        
    }
    elseif ($($Data.SSL3ServerValue1) -eq $($Config.ExpectedSSL3SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is disabled. &#9989</td>
        </tr>
"@
        Write-Log "SSL 3.0 Server is disabled."
        
    }

	if ($($Data.SSL3ServerValue2) -ne $($Config.ExpectedSSL3SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "SSL 3.0 Server is not disabled by default."
        
    }
    elseif ($($Data.SSL3ServerValue2) -eq $($Config.ExpectedSSL3SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SSL 3.0 Server is disabled by default. &#9989</td>
"@
        Write-Log "SSL 3.0 Server is disabled by default."
        
    }
	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@


	Add-HtmlBlock @"
	<h4>TLS 1.0 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.TLS1ClientValue1) -ne $($Config.ExpectedTLS1CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client not disabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.0 Client is not disabled."
        
    }
    elseif ($($Data.TLS1ClientValue1) -eq $($Config.ExpectedTLS1CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is disabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.0 Client is disabled."
        
    }

	if ($($Data.TLS1ClientValue2) -ne $($Config.ExpectedTLS1CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.0 Client is not disabled by default."
        
    }
    elseif ($($Data.TLS1ClientValue2) -eq $($Config.ExpectedTLS1CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Client is disabled by default. &#9989</td>
"@
        Write-Log "TLS 1.0 Client is disabled by default."
        
    }


	if ($($Data.TLS1ServerValue1) -ne $($Config.ExpectedTLS1SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server not disabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.0 Server is not disabled."
        
    }
    elseif ($($Data.TLS1ServerValue1) -eq $($Config.ExpectedTLS1SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is disabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.0 Server is disabled."
        
    }

	if ($($Data.TLS1ServerValue2) -ne $($Config.ExpectedTLS1SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.0 Server is not disabled by default."
        
    }
    elseif ($($Data.TLS1ServerValue2) -eq $($Config.ExpectedTLS1SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.0 Server is disabled by default. &#9989</td>
"@
        Write-Log "TLS 1.0 Server is disabled by default."
        
    }
	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@

	Add-HtmlBlock @"
	<h4>TLS 1.1 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.TLS1_1ClientValue1) -ne $($Config.ExpectedTLS11CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client not disabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.1 Client is not disabled."
        
    }
    elseif ($($Data.TLS1_1ClientValue1) -eq $($Config.ExpectedTLS11CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is disabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.1 Client is disabled."
        
    }

	if ($($Data.TLS1_1ClientValue2) -ne $($Config.ExpectedTLS11CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.1 Client is not disabled by default."
        
    }
    elseif ($($Data.TLS1_1ClientValue2) -eq $($Config.ExpectedTLS11CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Client is disabled by default. &#9989</td>
"@
        Write-Log "TLS 1.1 Client is disabled by default."
        
    }


	if ($($Data.TLS1_1ServerValue1) -ne $($Config.ExpectedTLS11SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server not disabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.1 Server is not disabled."
        
    }
    elseif ($($Data.TLS1_1ServerValue1) -eq $($Config.ExpectedTLS11SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is disabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.1 Server is disabled."
        
    }

	if ($($Data.TLS1_1ServerValue2) -ne $($Config.ExpectedTLS11SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is not disabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.1 Server is not disabled by default."
        
    }
    elseif ($($Data.TLS1_1ServerValue2) -eq $($Config.ExpectedTLS11SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.1 Server is disabled by default. &#9989</td>
"@
        Write-Log "TLS 1.1 Server is disabled by default."
        
    }
	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@


	Add-HtmlBlock @"
	<h4>TLS 1.2 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.TLS1_2ClientValue1) -ne $($Config.ExpectedTLS12CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client not enabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.2 Client is not enabled."
        
    }
    elseif ($($Data.TLS1_2ClientValue1) -eq $($Config.ExpectedTLS12CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is enabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.2 Client is enabled."
        
    }

	if ($($Data.TLS1_2ClientValue2) -ne $($Config.ExpectedTLS12CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is not enabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.2 Client is not enabled by default."
        
    }
    elseif ($($Data.TLS1_2ClientValue2) -eq $($Config.ExpectedTLS12CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Client is enabled by default. &#9989</td>
"@
        Write-Log "TLS 1.2 Client is enabled by default."
        
    }


	if ($($Data.TLS1_2ServerValue1) -ne $($Config.ExpectedTLS12SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server not enabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.2 Server is not enabled."
        
    }
    elseif ($($Data.TLS1_2ServerValue1) -eq $($Config.ExpectedTLS12SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is enabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.2 Server is enabled."
        
    }

	if ($($Data.TLS1_2ServerValue2) -ne $($Config.ExpectedTLS12SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is not enabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.2 Server is not enabled by default."
        
    }
    elseif ($($Data.TLS1_2ServerValue2) -eq $($Config.ExpectedTLS12SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.2 Server is enabled by default. &#9989</td>
"@
        Write-Log "TLS 1.2 Server is enabled by default."
        
    }
	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@


	Add-HtmlBlock @"
	<h4>TLS 1.3 Configuration</h4>
	<table>
	<tbody>
"@
    if ($($Data.TLS1_3ClientValue1) -ne $($Config.ExpectedTLS13CltV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client not enabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.3 Client is not enabled."
        
    }
    elseif ($($Data.TLS1_3ClientValue1) -eq $($Config.ExpectedTLS13CltV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is enabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.3 Client is enabled."
        
    }

	if ($($Data.TLS1_3ClientValue2) -ne $($Config.ExpectedTLS13CltV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is not enabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.3 Client is not enabled by default."
        
    }
    elseif ($($Data.TLS1_3ClientValue2) -eq $($Config.ExpectedTLS13CltV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Client is enabled by default. &#9989</td>
"@
        Write-Log "TLS 1.3 Client is enabled by default."
        
    }


	if ($($Data.TLS1_3ServerValue1) -ne $($Config.ExpectedTLS13SrvV1)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server not enabled. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.3 Server is not enabled."
        
    }
    elseif ($($Data.TLS1_3ServerValue1) -eq $($Config.ExpectedTLS13SrvV1)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is enabled. &#9989</td>
        </tr>
"@
        Write-Log "TLS 1.3 Server is enabled."
        
    }

	if ($($Data.TLS1_3ServerValue2) -ne $($Config.ExpectedTLS13SrvV2)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is not enabled by default. &#10060</td>
        </tr>
"@

       Write-Log "TLS 1.3 Server is not enabled by default."
        
    }
    elseif ($($Data.TLS1_3ServerValue2) -eq $($Config.ExpectedTLS13SrvV2)){
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>TLS 1.3 Server is enabled by default. &#9989</td>
"@
        Write-Log "TLS 1.3 Server is enabled by default."
        
    }

	#Finish Table
    Add-HtmlBlock @"
	</tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write Cert Padding Check Information
# ---------------------------------------------------------
function Write-CertPadChkHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Certificate Padding Check Configuration</h3>
	<table>
	<tbody>
"@
	
    if ($($Data.PaddingRegValue1) -eq $($Config.ExpectedCertPadChk)) {

        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Certificate Padding Check is enabled. &#9989</td>
        </tr>
"@

        Write-Log "CertPaddingCheck is activated."
        
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Certificate Padding Check is not enabled. &#10060</td>
        </tr>
"@
        Write-Log "CertPaddingCheck is not activated."
        
    }
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Certificate Padding Check should be enabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>This setting controls whether the padding check is enabled or disabled during the validation of certificates. Padding is a mechanism used in cryptography to adjust data to a specific length required by encryption algorithms. In the case of certificates, padding may be necessary to adjust the data to a certain block size. The padding check ensures that no insecure or incorrect padding values are present in the certificates, which could lead to security vulnerabilities.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write TLS Cipher Suites Information
# ---------------------------------------------------------
function Write-TLSCipherSuitesHtml {
	param($Data)

	$disabledCiphers = @(
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_RC4_128_MD5",
		"TLS_RSA_WITH_DES_CBC_SHA",
		"TLS_DHE_DSS_WITH_DES_CBC_SHA",
		"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
		"TLS_RSA_WITH_NULL_MD5",
		"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
	)

	Add-HtmlBlock @"
    <h3>TLS Cipher Suite Configuration</h3>
	<table>
	<tbody>
	<tr>
    <th>Name</th>
    <th>Status</th>
    </tr>
"@
    foreach ($cipher in $disabledCiphers) {
		if ($Data.Name -contains $cipher) {
			Write-Log "Cipher '$($cipher)' is not disabled."
			Add-HtmlBlock @"
	<tr>
	<td>Cipher '$($cipher)'</td>
	<td>Is not disabled. &#10060</td>
	</tr>
"@
		}
		else{
			Write-Log "Cipher '$($cipher)' is disabled."
			Add-HtmlBlock @"
	<tr>
	<td>Cipher '$($cipher)'</td>
	<td>Is disabled. &#9989</td>
	</tr>
"@
		}
	}

	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write LLMNR Information
# ---------------------------------------------------------
function Write-LLMNRHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Link-Local Multicast Resolution (LLMNR) Configuration</h3>
	<table>
	<tbody>
"@

	if ($($Data.LLMNRStatus) -eq $($Config.ExpectedLLMNR)) {
		Write-Log "Link-Local Multicast Resolution (LLMNR) is disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Link-Local Multicast Resolution (LLMNR) is disabled. &#9989</td>
        </tr>
"@
    }
	else{ 
		Write-Log "Link-Local Multicast Resolution (LLMNR) is not disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Link-Local Multicast Resolution (LLMNR) is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write WDigest Information
# ---------------------------------------------------------
function Write-WDigestHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>WDigest Credential Caching Configuration</h3>
	<table>
	<tbody>
"@

	if ($($Data.WDigestStatus) -eq $($Config.ExpectedWDigest)) {
		Write-Log "WDigest Credential Caching is disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>WDigest Credential Caching is disabled. &#9989</td>
        </tr>
"@
    }
	else{ 
		Write-Log "WDigest Credential Caching is not disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>WDigest Credential Caching is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write LSASS Information
# ---------------------------------------------------------
function Write-LSASSHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>LSASS Configuration</h3>
	<table>
	<tbody>
"@

	if ($($Data.LSASSStatus) -eq $($Config.ExpectedLSASS)) {
		Write-Log "LSASS is running as a protected process."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>LSASS is running as a protected process. &#9989</td>
        </tr>
"@
    }
	else{ 
		Write-Log "LSASS is not running as a protected process."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>LSASS is not running as a protected process. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write SMBv1 Information
# ---------------------------------------------------------
function Write-SMB1Html {
	param($Data)

	Add-HtmlBlock @"
    <h3>SMBv1 Configuration</h3>
	<table>
	<tbody>
"@
	if($($Config.ExpectedSMBv1) -eq 0){
		$ExpectedState = "Disabled"
	}
	if($($Config.ExpectedSMBv1) -eq 1) {
		$ExpectedState = "Enabled"
	}

	foreach ($SMB1Feature in $Data.SMB1Status) {
		
		if ($($SMB1Feature.State) -ne $ExpectedState) {
			Write-Log "$($SMB1Feature.FeatureName) is installed."
			Add-HtmlBlock @"
	<tr>
			<td>Implemented Setting:</td>
			<td>$($SMB1Feature.FeatureName) is installed. &#10060</td>
			</tr>
"@
		}
		elseif ($($SMB1Feature.State) -eq $ExpectedState) {
			Write-Log "$($SMB1Feature.FeatureName) is not installed. Nothing to do."
			Add-HtmlBlock @"
			<tr>
			<td>Implemented Setting:</td>
			<td>$($SMB1Feature.FeatureName) is not installed. &#9989</td>
			</tr>
"@
		} 
		else {
			Write-Log "ERROR: Cannot fetch $($SMB1Feature.FeatureName) information."
			Add-HtmlBlock @"
			<tr>
			<td>Implemented Setting:</td>
			<td>Cannot fetch $($SMB1Feature.FeatureName) information. &#10060</td>
			</tr>
"@
		}
	}

	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>SMBv1 Features should not be installed.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>SMB (Server Message Block) is a network-layered protocol mainly used on Windows for sharing files, printers, and communication between network-attached computers.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write SMBv3 Information
# ---------------------------------------------------------
function Write-SMB3Html {
	param($Data)

	Add-HtmlBlock @"
    <h3>SMBv3 Configuration</h3>
	<table>
	<tbody>
"@
	
	if($($Config.ExpectedSMBv3) -eq 1) {
		$SignatureState = $true
		$EncryptionState = $true
		$SecurityState = $true
	}


	if ($($Data.SMB3Signature) -ne $SignatureState) {
		Write-Log "SMBv3 Signature configuration is not enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Signature configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 Signature configuration is already enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Signature configuration is active. &#9989</td>
        </tr>
"@
	}

	if ($($Data.SMB3Encryption) -ne $EncryptionState) {
		Write-Log "SMBv3 encryption is not enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Encryption configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 encryption is already enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Encryption configuration is active. &#9989</td>
        </tr>
"@
	}

	if ($($Data.SMB3Security) -ne $SecurityState) {
		Write-Log "SMBv3 security is not enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Security configuration is not active. &#10060</td>
        </tr>
"@
	} else {
		Write-Log "SMBv3 security is already enabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>SMBv3 Security configuration is active. &#9989</td>
        </tr>
"@
	}

	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@
}


# ---------------------------------------------------------
# Write Builtin Administrator Information
# ---------------------------------------------------------
function Write-BuiltinAdminHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Built-in Administrator Account</h3>
	<table>
	<tbody>
"@

	
    if ($($Data.BuiltinAdminStatus) -eq $($Config.ExpectedBuiltinAdminEnabled)) {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The Built-in 'Administrator' user account is disabled. &#9989</td>
        </tr>
"@
        
		Write-Log "The Built-in 'Administrator' user account is disabled."
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The Built-in 'Administrator' user account is enabled. &#10060</td>
        </tr>
"@
        
		Write-Log "ERROR: The Built-in 'Administrator' user account is enabled."
    }
	
	#Finish Table
    Add-HtmlBlock @"
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


# ---------------------------------------------------------
# Write Local Admin Password Information
# ---------------------------------------------------------
function Write-LocalAdminPWHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Local Administrator Password Settings</h3>
	<table>
	<tbody>
"@

	if($Config.ExpectedAdminPWExpiracy -eq 0){
		$Expiracy = $null
	}

	if ($($Data.LocalAdminPWStatus) -eq $Expiracy) {
		Write-Log "$($Config.LocalAdminUser) has 'Password never expires' set to true."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>User $($Config.LocalAdminUser) has 'Password never expires' set to true. &#9989</td>
        </tr>
"@
    }
    else {
		Write-Log "ERROR: $($Config.LocalAdminUser) has 'Password never expires' set to false."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>User $($Config.LocalAdminUser) has 'Password never expires' set to false. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>The 'Password never expires' setting should be set to true.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Setting “Password never expires” for a local user ensures that the account remains accessible without forced password changes. This is especially important for system service accounts, deployment accounts, or automated maintenance users, where password expiration could break scripts, scheduled tasks, or critical services. It prevents unexpected lockouts and keeps automated processes running reliably.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write RDP Information
# ---------------------------------------------------------
function Write-RDPHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Remote Desktop Protocol Settings</h3>
	<table>
	<tbody>
"@

	if ($($Data.RDPStatus) -ne $($Config.ExpectedRDPStatus)) {
		Write-Log "Remote Desktop Protocol is enabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Protocol is enabled. &#9989</td>
        </tr>
"@
	}
	else {
		Write-Log "ERROR: Remote Desktop Protocol is disabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Protocol is disabled. &#10060</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write RDP Authentication Information
# ---------------------------------------------------------
function Write-RDPAuthHtml {
	param($Data)

	Add-HtmlBlock @"
    <h4>RDP Authentication Settings</h4>
	<table>
	<tbody>
"@

	if ($($Data.RDPNetAuth) -eq $($Config.ExpectedRDPNetAuth)) {
		Write-Log "RDP Network-Level user authentication is disabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>RDP Network-Level user authentication is disabled. &#9989</td>
        </tr>
"@
	}
	else {
		Write-Log "ERROR: RDP Network-Level user authentication is enabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>RDP Network-Level user authentication is enabled. &#10060</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>RDP Network-Level user authentication should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>RDP Network-Level user authentication restricts access to the PC. If enabled, users have to authenticate themselves to the network before they can connect to the PC. This makes no sense in this state of implementation of the PC. RDP Sessions are secured by Group Policy Settings in a domain.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write Location Service Information
# ---------------------------------------------------------
function Write-LocationSvcHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Location Service</h3>
	<table>
	<tbody>
"@

	if($($Config.ExpectedLocationSvc) -eq 0){
		$Expected = "Deny"
	}
    
    if ($($Data.LocationSvcStatus) -eq $Expected) {
		Write-Log "Location Service is disabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Location Service is disabled. &#9989</td>
        </tr>
"@
    }
    else {
		Write-Log "ERROR: Location Service is enabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Location Service is enabled. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write Network Window Information
# ---------------------------------------------------------
function Write-NetLocalHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>New Network Window</h3>
	<table>
	<tbody>
"@

	if($($Config.ExpectedNetWindow) -eq 0){
		$Expected = $null
	}

	if ($($Data.NetLocalStatus) -eq $Expected) {
		Write-Log "Network Localization is disabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Network Localization for 'New Network Window' is disabled. &#9989</td>
        </tr>
"@
    }
    else {
		Write-Log "ERROR: Network Lokalization is enabled."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Network Localization for 'New Network Window' is enabled. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Network Localization for 'New Network Window' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>By default, the first time you connect to a new network (wired or wireless), you will be prompted "Do you want to allow your PC to be discoverable by other PCs and devices on this network?" by the Network Location wizard. So we recommend to turn this off by default.</td>
	</tr>
    </tbody>
    </table>
"@
}


# ---------------------------------------------------------
# Write WinRM Information
# ---------------------------------------------------------
function Write-WinRMHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>WinRM Service Status</h3>
	<table>
	<tbody>
"@

	if($Config.ExpectedWinRM -eq 1){
		$Expected = "Running"
	}
	

	if ($($Data.WinRMStatus) -eq $Expected) {
		Write-Log "$($Data.WinRMDisplayName) - $($Data.WinRMName) is up and running."
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>$($Data.WinRMDisplayName) - $($Data.WinRMName) is up and running. &#9989</td>
        </tr>
"@
    }
    else {
        
		Write-Log "ERROR: $($Data.WinRMDisplayName) - $($Data.WinRMName) is not running. Current State is: $($Data.WinRMStatus)"		
		
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>$($Data.WinRMDisplayName) - $($Data.WinRMName) is not running. &#10060</td>
        </tr>
"@
    }
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>$($Data.WinRMDisplayName) - $($Data.WinRMName) should be enabled and running.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>We need WinRM in our environments for automatization tools like Software deployment and updates/upgrades to do these jobs remotely. Securtity settings are made via GPO settings in domain.</td>
	</tr>
    </tbody>
    </table>
"@

}



# ---------------------------------------------------------
# Write SNMP Feature Information
# ---------------------------------------------------------
function Write-SNMPHtml{	
	param($Data)

	Add-HtmlBlock @"
    <h3>SNMP Windows Feature on Demand</h3>
"@

	$SNMP = $($Data.SNMPFeature)
	$Name = $SNMP.DisplayName
	$State = $SNMP.State

	if ($($State) -eq 'Installed') {
		Write-Log "SNMP FoD is installed."
		Add-HtmlBlock @"
		<p>Name: Simple Network Management-Protokoll (SNMP)</p>
		<p>Description: The Microsoft Windows implementation of the Simple Network Management Protocol (SNMP) is used to configure remote devices, monitor network performance, audit network usage, and detect network faults or inappropriate access.</p>
		<p>Status Enabled: SNMP FoD is installed.</p>
"@
	}
	else {
		Write-Log "SNMP FoD is not installed."
		Add-HtmlBlock @"
		<p>Name: Simple Network Management-Protokoll (SNMP)</p>
		<p>Description: The Microsoft Windows implementation of the Simple Network Management Protocol (SNMP) is used to configure remote devices, monitor network performance, audit network usage, and detect network faults or inappropriate access.</p>
		<p>Status Enabled: SNMP FoD is not installed.</p>
"@
	}
}


# ---------------------------------------------------------
# Write RDP Firewall Rule Information
# ---------------------------------------------------------
function Write-RDPFirewallHtml {
	param($Data)

	Add-HtmlBlock @"
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

	$RuleDisplayNameList = @()
    $RuleDisplayGroupList = @()
    $RuleDescriptionList = @()
    $RuleStatusList = @()

	#Fill Table with content
    foreach ($FWRule in $($Data.RDPFWRules)) {
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
		
		Add-HtmlBlock @"
        <tr>
        <td>$FWRuleStat</td>
        <td>$FWRuleName</td>
		<td>$FWGroup</td>
		<td>$FWRuleDesc</td>
        </tr>
"@

    }
	
	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}


# ---------------------------------------------------------
# Write ICMP Firewall Rule Information
# ---------------------------------------------------------
function Write-ICMPFirewallHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>ICMP v4 Firewall Rules</h3>
    <table>
    <tbody>
    <tr>
	<th>Status</th>
    <th>Name</th>
	<th>Description</th>
    </tr>
"@

	$ICMPProfile = $($Data.ICMPAllowed)

	if ($ICMPProfile.Enabled -eq 'True') {
        
		Add-HtmlBlock @"
        <tr>
        <td>True</td>
        <td>ICMP Allow incoming V4 echo request</td>
		<td>Incoming ICMP V4 echo requests are allowed in '$($ICMPProfile.Profile)' profile through local firewall.</td>
        </tr>
"@
		Write-Log "Incoming ICMP V4 echo requests are allowed in '$($ICMPProfile.Profile)' profile through local firewall."
    }
    else {
        
		Add-HtmlBlock @"
        <tr>
        <td>False</td>
        <td>ICMP Allow incoming V4 echo request</td>
		<td>Incoming ICMP V4 echo requests are not allowed through local firewall.</td>
        </tr>
"@
		Write-Log "Incoming ICMP V4 echo requests are not allowed through local firewall."
    }
	
	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@
}


# ---------------------------------------------------------
# Write Windows Firewall Profile Information
# ---------------------------------------------------------
function Write-FirewallProfilesHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Windows Firewall Status</h3>
    <table>
    <tbody>
    <tr>
    <th>Scope</th>
    <th>Enabled</th>
    </tr>
"@

	$FWProfileNameList = @()
    $FWProfileStatusList = @()

	#Fill Table with content
    foreach ($FWProfile in $($Data.FirewallProfiles)) {
        $FWProfileNameList += $FWProfile.Name
        $FWProfileStatusList += $FWProfile.Enabled
    }

	for(($x = 0); $x -lt $FWProfileNameList.Count; $x++) {
        $FWProfileName = $FWProfileNameList[$x]
        $FWProfileStatus = $FWProfileStatusList[$x]
		
		Write-Log "Scope:        $FWProfileName"
		Write-Log "Enabled:      $FWProfileStatus"
		
		Add-HtmlBlock @"
        <tr>
        <td>$FWProfileName</td>
        <td>$FWProfileStatus</td>
        </tr>
"@

    }
	
	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write IPv6 Information
# ---------------------------------------------------------
function Write-IPv6Html {
	param($Data)

	Add-HtmlBlock @"
    <h3>IPv6 Network Setting</h3>
	<table>
	<tbody>
"@

	if ($($Data.IPv6Setting) -eq $($Config.ExpectedIPv6)) {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>IPv6 on Network Adapter '$($Data.AdapterName)' is disabled. &#9989</td>
        </tr>
"@
        
		Write-Log "IPv6 on Network Adapter '$($Data.AdapterName)' is disabled."
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>IPv6 on Network Adapter '$($Data.AdapterName)' is enabled. &#10060</td>
        </tr>
"@
        
		Write-Log "ERROR: IPv6 on Network Adapter '$($Data.AdapterName)' is enabled."
    }
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write First Logon Animation Information
# ---------------------------------------------------------
function Write-FirstLogonHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>First Logon Animation</h3>
	<table>
	<tbody>
"@

	if ($($Data.AnimationStatus) -ne $($Config.ExpectedLogonAnimation)) {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'First Logon Animation' is enabled. &#10060</td>
        </tr>
"@
        
		Write-Log "ERROR: The 'First Logon Animation' is enabled."
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'First Logon Animation' is disabled. &#9989</td>
        </tr>
"@
        
		Write-Log "The 'First Logon Animation' is disabled."
    }

	Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write Delayed Desktop Switch Information
# ---------------------------------------------------------
function Write-DelayedSwitchHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Delayed Desktop Switch</h3>
	<table>
	<tbody>
"@

    if ($($Data.DesktopSwitchStatus) -ne $($Config.ExpectedDelayedDesktopSwitch)) {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'Delayed Desktop Switch' is enabled. &#10060</td>
        </tr>
"@
        
		Write-Log "ERROR: The 'Delayed Desktop Switch' is enabled."
    }
    else {
        Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>The 'Delayed Desktop Switch' is disabled. &#9989</td>
        </tr>
"@
        
		Write-Log "The 'Delayed Desktop Switch' is disabled."
    }
	
	#Finish Table
    Add-HtmlBlock @"
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

# ---------------------------------------------------------
# Write WSUS Settings Information
# ---------------------------------------------------------
function Write-WSUSHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>WSUS Information</h3>
"@

	$WUInfo = $($Data.WSUSInfo)
	$WUServer = $WUInfo.WUServer
	$WUStatusSrv = $WUInfo.WUStatusServer

	if ($WUInfo.ElevateNonAdmins -eq 1) {
        $ElevateNonAdmins = "Users in the Users security group are allowed to approve or disapprove updates."
    }
	elseif ($WUInfo.ElevateNonAdmins -eq 0) {
         $ElevateNonAdmins = "Only users in the Administrators user group can approve or disapprove updates."
    }
    elseif ($WUInfo.ElevateNonAdmins -ne 0 -and $WUInfo.ElevateNonAdmins -ne 1) {
        $ElevateNonAdmins = "Not Set."
    }
    

    if ($WUInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
        $InternetConnect = "Connections to public Microsoft services (update service) will no longer be established."
    }
	elseif ($WUInfo.DoNotConnectToWindowsUpdateInternetLocations -eq 0) {
         $InternetConnect = "Connections to Microsoft services are established at regular intervals. (Default)"
    }
    elseif ($WUInfo.DoNotConnectToWindowsUpdateInternetLocations -ne 0 -and $WUInfo.DoNotConnectToWindowsUpdateInternetLocations -ne 1) {
        $InternetConnect = "Not Set."
    }
	

    if ($WUInfo.SetUpdateNotificationLevel -eq 1) {
        $SetNotificationLevel = "Notifications are enabled."
    }
	elseif ($WUInfo.SetUpdateNotificationLevel -eq 0) {
         $SetNotificationLevel = "Notifications are disabled."
    }
    elseif ($WUInfo.SetUpdateNotificationLevel -ne 1 -and $WUInfo.SetUpdateNotificationLevel -ne 0) {
        $SetNotificationLevel = "Not Set."
    }
	

    if ($WUInfo.UpdateNotificationLevel -eq 1) {
        $UpateNotificationLevel = "Disable all notifications, excluding restart warnings."
    }
	elseif ($WUInfo.UpdateNotificationLevel -eq 0) {
        $UpateNotificationLevel = "Default OS Windows Update notifications."
    }
    elseif ($WUInfo.UpdateNotificationLevel -eq 2) {
        $UpateNotificationLevel = "Disable all notifications, including restart warnings."
    }
    elseif ($WUInfo.UpdateNotificationLevel -ne 1 -and $WUInfo.UpdateNotificationLevel -ne 0 -and $WUInfo.UpdateNotificationLevel -ne 2) {
        $UpateNotificationLevel = "Not Set."
    }

	Write-Log "Windows Update Server:                                             $WUServer"
	Write-Log "Status Server:                                                     $WUStatusSrv"
	Write-Log "NonAdmins Elevation:                                               $ElevateNonAdmins"
	Write-Log "Do Not Connect to Microsoft Windows Update Internet Locations:     $InternetConnect"
	Write-Log "Set Update Notification Level:                                     $SetNotificationLevel"
	Write-Log "Update Notification Level:                                         $UpateNotificationLevel"

	Add-HtmlBlock @"
	<p>Windows Update Server: $WUServer</p>
	<p>Status Server: $WUStatusSrv</p>
	<p>NonAdmins Elevation: $ElevateNonAdmins</p>
	<p>Do Not Connect to Microsoft Windows Update Internet Locations: $InternetConnect</p>
	<p>Set Update Notification Level: $SetNotificationLevel</p>
	<p>Update Notification Level: $UpateNotificationLevel</p>
"@

}


# ---------------------------------------------------------
# Write WSUS Options Status
# ---------------------------------------------------------
function Write-WSUSOptionsHtml {
	param($Data)

	Add-HtmlBlock @"
    <h4>WSUS Advanced Settings</h4>
"@

	$GetWUOptions = $Data.WSUSOptions

	if ($GetWUOptions.AUOptions -eq 2) {
        $AUOptions = "Notify before download."
    }
	elseif ($GetWUOptions.AUOptions -eq 3) {
         $AUOptions = "Automatically download and notify of installation."
    }
    elseif ($GetWUOptions.AUOptions -eq 4) {
         $AUOptions = "Automatic download and scheduled installation. (Opnly valid if 'Scheduled Install Settings' are configured!)"
    }
    elseif ($GetWUOptions.AUOptions -eq 5) {
         $AUOptions = "Automatic Updates is required, but end users can configure it."
    }
    elseif ($GetWUOptions.AUOptions -ne 2 -and $GetWUOptions.AUOptions -ne 3 -and $GetWUOptions.AUOptions -ne 4 -and $GetWUOptions.AUOptions -ne 5) {
         $AUOptions = "Not Set."
    }

	if ($GetWUOptions.UseWUServer -eq 0) {
        $UseWUServer = "The client connects directly to the Windows Update site (http://windowsupdate.microsoft.com) on the Internet."
    }
	elseif ($GetWUOptions.UseWUServer -eq 1) {
         $UseWUServer = "The client connects to the specified local update service (WSUS)."
    }
    elseif ($GetWUOptions.UseWUServer -ne 0 -and $GetWUOptions.UseWUServer -ne 1) {
         $UseWUServer = "Not Set."
    }

	if ($GetWUOptions.NoAutoRebootWithLoggedOnUsers -eq 0) {
        $NoAutoRebootWithLoggedOnUsers = "Automatic Updates notifies user that the computer will restart in 5 minutes."
    }
	elseif ($GetWUOptions.NoAutoRebootWithLoggedOnUsers -eq 1) {
         $NoAutoRebootWithLoggedOnUsers = "Logged-on user gets to choose whether or not to restart his or her computer."
    }
    elseif ($GetWUOptions.NoAutoRebootWithLoggedOnUsers -ne 0 -and $GetWUOptions.NoAutoRebootWithLoggedOnUsers -ne 1) {
          $NoAutoRebootWithLoggedOnUsers = "Not Set."
    }

	if ($GetWUOptions.NoAutoUpdate -eq 0) {
        $NoAutoUpdate = "Automatic Updates are enabled."
    }
	elseif ($GetWUOptions.NoAutoUpdate -eq 1) {
         $NoAutoUpdate = "Automatic Updates are disabled."
    }
    elseif ($GetWUOptions.NoAutoUpdate -ne 0 -and $GetWUOptions.NoAutoUpdate -ne 1) {
         $NoAutoUpdate = "Not Set."
    }

	if ($GetWUOptions.ScheduledInstallDay -eq 0) {
        $ScheduledInstallDay = "Updates will be installed every day."
    }
	elseif ($GetWUOptions.ScheduledInstallDay -eq 1) {
         $ScheduledInstallDay = "Updates will be installed on Sunday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 2) {
         $ScheduledInstallDay = "Updates will be installed on Monday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 3) {
         $ScheduledInstallDay = "Updates will be installed on Tuesday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 4) {
         $ScheduledInstallDay = "Updates will be installed on Wednesday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 5) {
         $ScheduledInstallDay = "Updates will be installed on Thursday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 6) {
         $ScheduledInstallDay = "Updates will be installed on Friday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -eq 7) {
         $ScheduledInstallDay = "Updates will be installed on Saturday."
    }
    elseif ($GetWUOptions.ScheduledInstallDay -ne 0 -and $GetWUOptions.ScheduledInstallDay -ne 1 -and $GetWUOptions.ScheduledInstallDay -ne 2 -and $GetWUOptions.ScheduledInstallDay -ne 3 -and $GetWUOptions.ScheduledInstallDay -ne 4 -and $GetWUOptions.ScheduledInstallDay -ne 5 -and $GetWUOptions.ScheduledInstallDay -ne 6 -and $GetWUOptions.ScheduledInstallDay -ne 7) {
          $ScheduledInstallDay = "Not Set."
    }

	$Hours = @(0..23)
    if ($Hours -contains $GetWUOptions.ScheduledInstallTime) {
        $ScheduledInstallTime = "Updates will be installed on a specific time of day."
    }
	elseif ($Hours -notcontains $GetWUOptions.ScheduledInstallTime) {
         $ScheduledInstallTime = "This setting is not configred."
    }

	Write-Log "Automatic Update Options:                                    $AUOptions"
	Write-Log "Windows Update Settings:                                     $UseWUServer"
	Write-Log "Atomatic Reboot while Users are logged on:                   $NoAutoRebootWithLoggedOnUsers"
	Write-Log "Automatic Update Setting:                                    $NoAutoUpdate"
	Write-Log "Setting on which day updates will be installed:              $ScheduledInstallDay"
	Write-Log "Setting when updates will be installed on a specific day:    $ScheduledInstallTime"
	
	Add-HtmlBlock @"
	<p>Automatic Update Options: $AUOptions</p>
	<p>Windows Update Settings: $UseWUServer</p>
	<p>Atomatic Reboot while Users are logged on: $NoAutoRebootWithLoggedOnUsers</p>
	<p>Automatic Update Setting: $NoAutoUpdate</p>
	<p>Setting on which day updates will be installed: $ScheduledInstallDay</p>
	<p>Setting when updates will be installed on a specific day: $ScheduledInstallTime</p>
"@

}

# ---------------------------------------------------------
# Write OEM Info
# ---------------------------------------------------------
function Write-OEMHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>OEM Information</h3>
"@

	
	if($($Data.OEMImgBmpValue) -eq 1) {
		Write-Log "OEM Image '$($Config.OEMImageFile)' is available under 'C:\windows\system32\'."
		Add-HtmlBlock @"
		<p>OEM Image '$($Config.OEMImageFile)' is available under 'C:\windows\system32\'.</p>
        <img src="Media/oem/$($Config.OEMImageFile)" alt="Logo BMP">
"@
    }
    else {
		Write-Log "OEM Image file '$($Config.OEMImageFile)' could not be found under 'C:\windows\system32\'."
		Add-HtmlBlock @"
		<p>OEM Image file '$($Config.OEMImageFile)' could not be found under 'C:\windows\system32\'.</p>
"@
    }

	if($($Data.OEMUsrImgBmpValue) -eq 1) {
		Write-Log "OEM User Account Image '$($Config.OEMImageFile)' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>OEM User Account Image '$($Config.OEMImageFile)' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/$($Config.OEMImageFile)" alt="Logo BMP">
"@
    }
    else {
		Write-Log "OEM User Account Image could not be found under 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>OEM User Account Image could not be found under 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMGuestImgValue) -eq 1) {
		Write-Log "Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Images 'guest.bmp' and 'guest.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img class="default-guest" src="Media/oem/UserAccountPictures/guest.bmp" alt="Guest BMP">
        <img class="default-guest" src="Media/oem/UserAccountPictures/guest.png" alt="Guest Picture">
"@
    }
    else {
		Write-Log "Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Images 'guest.bmp' and 'guest.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMUsrImgValue) -eq 1) {
		Write-Log "Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Images 'user.bmp' and 'user.png' are available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img class="default-user" src="Media/oem/UserAccountPictures/user.bmp" alt="User BMP">
        <img class="default-user" src="Media/oem/UserAccountPictures/user.png" alt="User Picture">
"@
    }
    else {
		Write-Log "Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Images 'user.bmp' and 'user.png' are not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMUsr32ImgValue) -eq 1) {
		Write-Log "Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-32.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-32.png" alt="User Picture 32">
"@
    }
    else {
		Write-Log "Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-32.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMUsr40ImgValue) -eq 1) {
		Write-Log "Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-40.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-40.png" alt="User Picture 40">
"@
    }
    else {
		Write-Log "Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-40.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMUsr48ImgValue) -eq 1) {
		Write-Log "Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-48.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-48.png" alt="User Picture 48">
"@
    }
    else {
		Write-Log "Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-48.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMUsr192ImgValue) -eq 1) {
		Write-Log "Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-192.png' is available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
        <img src="Media/oem/UserAccountPictures/user-192.png" alt="User Picture 192">
"@
    }
    else {
		Write-Log "Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'."
		Add-HtmlBlock @"
		<p>Guest User Account Image 'user-192.png' is not available in 'C:\ProgramData\Microsoft\User Account Pictures\'.</p>
"@
    }

	if($($Data.OEMOOBEInfoValue) -eq 1) {
		Write-Log "OEM Image '$($Config.OEMImageFile)' is available in 'C:\windows\system32\oobe\info\'."
		Add-HtmlBlock @"
		<p>OEM Image '$($Config.OEMImageFile)' is available in 'C:\windows\system32\oobe\info\'.</p>
        <img src="Media/oem/$($Config.OEMImageFile)" alt="Logo BMP">
"@
    }
    else {
		Write-Log "OEM Image '$($Config.OEMImageFile)' is not available in 'C:\windows\system32\oobe\info\'."
		Add-HtmlBlock @"
		<p>OEM Image '$($Config.OEMImageFile)' is not available in 'C:\windows\system32\oobe\info\'.</p>
"@
    }

	if($($Data.OEMOOBEWallpaperValue) -eq 1) {
		Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\windows\system32\oobe\info\backgrounds\'."
		Add-HtmlBlock @"
		<p>OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\windows\system32\oobe\info\backgrounds\'.</p>
        <img class="default-wallpaper" src="Media/oem/$($Config.OEMWallpaperFile)" alt="Wallpaper">
"@
    }
    else {
		Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in C:\windows\system32\oobe\info\backgrounds\'.<"
		Add-HtmlBlock @"
		<p>OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in C:\windows\system32\oobe\info\backgrounds\'.</p>
"@
    }
    if($($Data.OEMWallpaperValue) -eq 1) {
		Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\Windows\Web\Wallpaper\Windows\'."
		Add-HtmlBlock @"
		<p>OEM Wallpaper '$($Config.OEMWallpaperFile)' is available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
        <img class="default-wallpaper" src="Media/oem/$($Config.OEMWallpaperFile)" alt="Wallpaper">
"@
    }
    else {
		Write-Log "OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in 'C:\Windows\Web\Wallpaper\Windows\'."
		Add-HtmlBlock @"
		<p>OEM Wallpaper '$($Config.OEMWallpaperFile)' is not available in 'C:\Windows\Web\Wallpaper\Windows\'.</p>
"@
    }



	$OEMValues = $Data.OEMValues
	$OEMManufacturer = $OEMValues.Manufacturer
	$OEMLogo = $OEMValues.Logo

	Write-Log "Manufacturer: $OEMManufacturer"
	Write-Log "Logo: $OEMLogo"

	Add-HtmlBlock @"
	<h4>OEM Registry Values</h4>
	<p>Manufacturer: $OEMManufacturer</p>
	<p>Logo: $OEMLogo</p>
"@
}

# ---------------------------------------------------------
# Write Power Plan Info
# ---------------------------------------------------------
function Write-PowerPlanHtml {
	param($Data)

	Write-Log "Name: $($data.PPlanName)"
	Write-Log "Description: $($Data.PPlanDesc)"
	Write-Log "Status Enabled: $($Data.PPlanActive)"

	Add-HtmlBlock @"
    <h3>PowerPlan Settings</h3>
	<p>Name: $($data.PPlanName)</p>
	<p>Description: $($Data.PPlanDesc)</p>
	<p>Status Enabled: $($Data.PPlanActive)</p>
"@
}

# ---------------------------------------------------------
# Write Power Plan Config Info
# ---------------------------------------------------------
function Write-PowerPlanConfigHtml {
	param($Data)

	Add-HtmlBlock @"
    <h4>PowerPlan Options</h4>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Plugged in Power Setting</th>
	<th>On Battery Power Setting</th>
    </tr>
"@

	$Data.PowerConfig | foreach-object {
		$Setting = $_.Setting
		$acReadValue = $_.ACValue
		$dcReadValue = $_.DCValue
		
		Write-Log "$Setting - $acReadValue - $dcReadValue"

		Add-HtmlBlock @"
	<tr>
	<td>$Setting</td>
	<td>$acReadValue</td>
	<td>$dcReadValue</td>
	</tr>
"@
        
	}

	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write Volume Information 
# ---------------------------------------------------------
function Write-VolumesHtml {
	param($Data)

	$VolumeDriveLetterList = @() #$Volumes.DriveLetter
    $VolumeFriendlyNameList = @() #$Volumes.FileSystemLabel
    $VolumeFileSystemList = @() #$Volumes.FileSystem
    #$VolumeFileSystemTypeList = @() #$Volumes.FileSystemType
	$VolumeDriveTypeList = @() #$Volumes.DriveType
	$VolumeHealthStatusList = @() #$Volumes.HealthStatus
	$VolumeOperationalStatusList = @() #$Volumes.OperationalStatus
	#$VolumeRemainingSizeList = @() #$Volumes.SizeRemaining
	$VolumeMaxSizeList = @() #$Volumes.Size


	Add-HtmlBlock @"
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

	foreach ($Volume in $($Data.Volumes)) {
        
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

		Write-Log "$VolumeName - $DriveLetter - $FileSystem - $DriveType - $HealthStatus - $OperationalStatus - $VolumeMaxSize GB"

		Add-HtmlBlock @"
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

	Add-HtmlBlock @"
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write BitLocker Status
# ---------------------------------------------------------
function Write-BitLockerHtml {
	param($Data)

	$VolumeTypeList = @()
    $VolumeDriveLetterList = @()
    #$VolumeKeyProtectorList = @()
    $VolumeProtectionStatusList = @()

	Add-HtmlBlock @"
    <h3>BitLocker Status Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Mount Point</th>
    <th>Volume Type</th>
    <th>Protection Status</th>
    </tr>
"@

	foreach ($Volume in $Data.Volumes) {
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

		Write-Log "$MountPoint - $VolumeType - $ProtectionStatus"

        Add-HtmlBlock @"
        <tr>
        <td>$MountPoint</td>
        <td>$VolumeType</td>
        <td>$ProtectionStatus</td>
        </tr>
"@
    }

    #Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write VSS Status
# ---------------------------------------------------------
function Write-VSSHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>VSS Settings</h3>
"@

	foreach ($Item in $Data.VSSConfig) {
		Write-Log "Maximum VSS Setting for Volume '$($Item.DriveLetter)': $($Item.MaxVSS)"
		Add-HtmlBlock @"
	<p>Maximum VSS Setting for Volume '$($Item.DriveLetter)': $($Item.MaxVSS)</p>
"@
	}
}

# ---------------------------------------------------------
# Write Local User Info
# ---------------------------------------------------------
function Write-LocalUsersInfoHtml {
	param($Data)

	$UserNameList = @() #$Users.Name
	$UserEnabledList = @() # $Users.Enabled
	$UserDescriptionList = @() #$Users.Description

	Add-HtmlBlock @"
    <h3>Local User Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Enabled</th>
    <th>Description</th>
    </tr>
"@

	foreach ($LocalUser in $($Data.LocalUsers)) {
			
		$UserNameList += $LocalUser.Name
		$UserEnabledList += $LocalUser.Enabled
		$UserDescriptionList += $LocalUser.Description

	}

	for(($x = 0); $x -lt $UserNameList.Count; $x++) {
		$UserName = $UserNameList[$x]
		$Status = $UserEnabledList[$x]
		$UserDescription = $UserDescriptionList[$x]

		Write-Log "$UserName - $Status - $UserDescription"

		Add-HtmlBlock @"
        <tr>
        <td>$UserName</td>
        <td>$Status</td>
        <td>$UserDescription</td>
        </tr>
"@
	}

	Add-HtmlBlock @"
    </tbody>
    </table>
"@

}


# ---------------------------------------------------------
# Write Local Group Info
# ---------------------------------------------------------
function Write-LocalGroupsInfoHtml {
	param($Data)

	$GroupNameList = @() #$Groups.Name
	$GroupDescriptionList = @() #$Groups.Description


	Add-HtmlBlock @"
    <h3>Local Group Information</h3>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Description</th>
    </tr>
"@

	foreach ($LocalGroup in $($Data.LocalGroups)) {
			
		$GroupNameList += $LocalGroup.Name
		$GroupDescriptionList += $LocalGroup.Description

	}

	for(($x = 0); $x -lt $GroupNameList.Count; $x++) {
		$GroupName = $GroupNameList[$x]
		$GroupDescription = $GroupDescriptionList[$x]

		Write-Log "$GroupName - $GroupDescription"

		Add-HtmlBlock @"
        <tr>
        <td>$GroupName</td>
        <td>$GroupDescription</td>
        </tr>
"@
	}

	Add-HtmlBlock @"
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write Installed Software Info
# ---------------------------------------------------------
function Write-SoftwareHtml {
	param($Data)

	$SoftwareNameList = @()
    $SoftwareVersionList = @()
    $SoftwareVendorList = @()

	Add-HtmlBlock @"
    <h3>Installed Software</h3>
	<h4>Installed Programs</h4>
    <table>
    <tbody>
    <tr>
    <th>Name</th>
    <th>Version</th>
    <th>Vendor</th>
    </tr>
"@

	foreach ($Software in $($Data.Software)) {
        $SoftwareNameList += $Software.DisplayName
        $SoftwareVersionList += $Software.DisplayVersion
        $SoftwareVendorList += $Software.Publisher
    }

	for(($x = 0); $x -lt $SoftwareNameList.Count; $x++) {
        $SWName = $SoftwareNameList[$x]
        $SWVersion = $SoftwareVersionList[$x]
        $SWVendor = $SoftwareVendorList[$x]

		Write-Log "$SWName - $SWVersion - $SWVendor"

        Add-HtmlBlock @"
        <tr>
        <td>$SWName</td>
        <td>$SWVersion</td>
        <td>$SWVendor</td>
        </tr>
"@
	}

	Add-HtmlBlock @"
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write Running Services Info
# ---------------------------------------------------------
function Write-ServicesHtml {
	param($Data)

	$SVCNameList = @()
    $SVCDescList = @()
    $SVCStateList = @()

	Add-HtmlBlock @"
    <h3>Default Active Services</h3>
    <table>
    <tbody>
    <tr>
    <th>State</th>
    <th>Name</th>
    <th>Display Name</th>
    </tr>
"@

	foreach ($Service in $($Data.Services)) {
        $SVCNameList += $Service.Name
        $SVCDescList += $Service.DisplayName
        $SVCStateList += $Service.Status
    }


    for(($x = 0); $x -lt $SVCNameList.Count; $x++) {
        $SVCName = $SVCNameList[$x]
        $SVCDesc = $SVCDescList[$x]
        $SVCState = $SVCStateList[$x]

		Write-Log "$SVCState - $SVCName - $SVCDesc"

        Add-HtmlBlock @"
        <tr>
        <td>$SVCState</td>
        <td>$SVCName</td>
        <td>$SVCDesc</td>
        </tr>
"@
    }

	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write Signed Drivers Info
# ---------------------------------------------------------
function Write-DriversHtml {
	param($Data)

	$DeviceNameList = @()
    $ManufacturerList = @()
    $DriverVersionList = @()
	
	#Create Table
    Add-HtmlBlock @"
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
    foreach ($Driver in $($Data.SignedDrivers)) {
        $DeviceNameList += $Driver.DeviceName
        $ManufacturerList += $Driver.Manufacturer
        $DriverVersionList += $Driver.DriverVersion
    }
	
	for(($x = 0); $x -lt $DeviceNameList.Count; $x++) {
        $DeviceName = $DeviceNameList[$x]
        $Manufacturer = $ManufacturerList[$x]
        $DriverVersion = $DriverVersionList[$x]

		Write-Log "$DeviceName - $Manufacturer - $DriverVersion"
		
		Add-HtmlBlock @"
        <tr>
        <td>$DeviceName</td>
        <td>$Manufacturer</td>
        <td>$DriverVersion</td>
        </tr>
"@
	}
	
	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}


# ---------------------------------------------------------
# Write Windows Server Roles and Features Status
# ---------------------------------------------------------
function Write-RolesFeaturesHtml {
	param($Data)

	$RFNameList = @()
    $RFStatusList = @()

	Add-HtmlBlock @"
    <h3>Installed Windows Roles and Features</h3>
    <table>
    <tbody>
    <tr>
    <th>State</th>
    <th>Name</th>
    </tr>
"@

	foreach ($Feature in $($Data.RolesFeatures)) {
        $RFNameList += $Feature.Name
        $RFStatusList += $Feature.InstallState
    }


    for(($x = 0); $x -lt $RFNameList.Count; $x++) {
        $FeatureName = $RFNameList[$x]
        $FeatureStatus = $RFStatusList[$x]

        Add-HtmlBlock @"
        <tr>
        <td>$FeatureName</td>
        <td>$FeatureStatus</td>
        </tr>
"@
    }

	#Finish Table
    Add-HtmlBlock @"
    </tbody>
    </table>
"@

}



<# ---------------------------------------------------------
### BACKUP SERVER SECURITY COMPLIANCE
#>

# ---------------------------------------------------------
# Write Windows Script Host Status
# ---------------------------------------------------------
function Write-WinScriptHostHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Windows Script Host Configuration</h3>
	<table>
	<tbody>
"@

	$State = $Data.WinScriptState
	if ($State.Enabled -eq "0") {
		Write-Log "Windows Script Host is disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Windows Script Host is disabled. &#9989</td>
        </tr>
"@
    }
	else{
		Write-Log "Windows Script Host is not disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Windows Script Host is not disabled. &#10060</td>
        </tr>
"@
    }

	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Windows Script Host should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>This Service is essential for Windows Deployment System. Regarding this reason, we can not disable this service during deployment.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write NetBIOS Status
# ---------------------------------------------------------
function Write-NetBiosHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>NetBIOS Protocol</h3>
	<table>
	<tbody>
"@

	if($($Data.NetBiosState)) {
		foreach($interface in $($Data.NetBiosState)) 
		{
			Write-Log "Fetch information from interface '$($interface)'."
			
			$NetBIOSSetting = Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$interface" -Name "NetbiosOptions"
			Write-Log "NetBIOS Setting for interface '$($interface)' is $($NetBIOSSetting)."
			if($NetBIOSSetting.NetbiosOptions -eq "2"){
				Write-Log "NetBIOS is disabled."
				Add-HtmlBlock @"
				<tr>
				<td>Network Interface $($interface):</td>
				<td>NetBIOS is disabled. &#9989</td>
				</tr>
"@
			}
			else{
				Write-Log "NetBIOS is not disabled."
				Add-HtmlBlock @"
				<tr>
				<td>Network Interface $($interface):</td>
				<td>NetBIOS is not disabled. &#10060</td>
				</tr>
"@
			}
		}

	}
	else{
		Write-Log "ERROR: No newtork interfaces present."
		Add-HtmlBlock @"
		<tr>
		<td>No Network Interface found.</td>
		<td>&#10060</td>
		</tr>
"@
	}
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>NetBIOS should be disabled on Network Interfaces.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>NetBIOS provides communication services on local networks. It uses a software protocol called NetBIOS Frames that allows applications and computers on a local area network to communicate with network hardware and to transmit data across the network.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write Windows HTTP Auto Proxy Status
# ---------------------------------------------------------
function Write-WinHttpProxyHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Web Proxy Auto-Discovery Service</h3>
	<table>
	<tbody>
"@

	$State = $Data.WinHttpAutoProxyState
	if ($State.Start -eq "4") {
		Write-Log "Web Proxy Auto-Discovery service is disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Web Proxy Auto-Discovery Service is disabled. &#9989</td>
        </tr>
"@
    }
	else{ 
		Write-Log "Web Proxy Auto-Discovery service is not disabled."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Web Proxy Auto-Discovery Service is not disabled. &#10060</td>
        </tr>
"@

    }

	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Web Proxy Auto-Discovery Service should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Web Proxy Auto-Discovery Service implements the client HTTP stack and provides developers with a Win32 API and COM Automation component for sending HTTP requests and receiving responses. In addition, WinHTTP provides support for auto-discovering a proxy configuration via its implementation of the Web Proxy Auto-Discovery (WPAD) protocol.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write WinRM Service Status
# ---------------------------------------------------------
function Write-WinRMSvcStatusHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Windows Remote Management Service</h3>
	<table>
	<tbody>
"@
	$WinRmSvc = $Data.WinRMInfo
	if ($WinRMSvc.StartType -eq 'Disabled') {
		Write-Log "$($WinRMSvc.DisplayName) - $($WinRMSvc.Name) is disabled. Current StartType is $($WinRMSvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Windows Remote Management Service '$($WinRMSvc.Name)' is disabled. &#9989</td>
        </tr>
"@
    }
	else{
		Write-Log "$($WinRMSvc.DisplayName) - $($WinRMSvc.Name) is not disabled. Current StartType is $($WinRMSvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Windows Remote Management Service '$($WinRMSvc.Name)' is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Windows Remote Management Service '$($WinRMSvc.Name)' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Windows Remote Management Service implements the WS-Management protocol for remote management. WS-Management is a standard web services protocol used for remote software and hardware management. The WinRM service listens on the network for WS-Management requests and processes them. The WinRM Service needs to be configured with a listener using winrm.cmd command line tool or through Group Policy in order for it to listen over the network. The WinRM service provides access to WMI data and enables event collection. Event collection and subscription to events require that the service is running. WinRM messages use HTTP and HTTPS as transports. The WinRM service does not depend on IIS but is preconfigured to share a port with IIS on the same machine.  The WinRM service reserves the /wsman URL prefix. To prevent conflicts with IIS, administrators should ensure that any websites hosted on IIS do not use the /wsman URL prefix.</td>
	</tr>
    </tbody>
    </table>
"@

}

# ---------------------------------------------------------
# Write Remote Registry Service Status
# ---------------------------------------------------------
function Write-RemoteRegSvcStatusHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Remote Registry Service</h3>
	<table>
	<tbody>
"@

	$RemoteRegistrySvc = $Data.RemoteRegistryInfo
	if ($RemoteRegistrySvc.StartType -eq 'Disabled') {
		Write-Log "$($RemoteRegistrySvc.DisplayName) - $($RemoteRegistrySvc.Name) is disabled. Current StartType is $($RemoteRegistrySvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Registry Service '$($RemoteRegistrySvc.Name)' is disabled. &#9989</td>
        </tr>
"@
    }
	else{
		Write-Log "$($RemoteRegistrySvc.DisplayName) - $($RemoteRegistrySvc.Name) is not disabled. Current StartType is $($RemoteRegistrySvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Registry Service '$($RemoteRegistrySvc.Name)' is not disabled. &#10060</td>
        </tr>
"@

    }
    
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Remote Registry Service '$($RemoteRegistrySvc.Name)' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Remote Registry Service enables remote users to modify registry settings on this computer. If this service is stopped, the registry can be modified only by users on this computer. If this service is disabled, any services that explicitly depend on it will fail to start.</td>
	</tr>
    </tbody>
    </table>
"@
}

# ---------------------------------------------------------
# Write Remote Desktop Service Status
# ---------------------------------------------------------
function Write-TermSvcStatusHtml {
	param($Data)

	Add-HtmlBlock @"
    <h3>Remote Desktop Service</h3>
	<table>
	<tbody>
"@
	
	$TermSvc = $Data.TermSvcInfo
    if ($TermSvc.StartType -eq 'Disabled') {
		Write-Log "$($TermSvc.DisplayName) - $($TermSvc.Name) is disabled. Current StartType is $($TermSvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Service '$($TermSvc.Name)' is disabled. &#9989</td>
        </tr>
"@
    }
	else { #($TermSvc.StartType -ne "Disabled") {
		Write-Log "$($TermSvc.DisplayName) - $($TermSvc.Name) is not disabled. Current StartType is $($TermSvc.StartType)."
		Add-HtmlBlock @"
		<tr>
        <td>Implemented Setting:</td>
        <td>Remote Desktop Service '$($TermSvc.Name)' is not disabled. &#10060</td>
        </tr>
"@

    }
	
	#Finish Table
    Add-HtmlBlock @"
	<tr>
	<td>Expected Setting:</td>
	<td>Remote Desktop Service '$($TermSvc.Name)' should be disabled.</td>
	</tr>
	<tr>
	<td>Description:</td>
	<td>Remote Desktop Service allows users to connect interactively to a remote computer. Remote Desktop and Remote Desktop Session Host Server depend on this service.</td>
	</tr>
    </tbody>
    </table>
"@

}



<# ---------------------------------------------------------


<#
### Section 5 - Main Report Generator (Start-DeploymentReport)
#>
function Start-DeploymentReport {
	param (
		[switch]$UploadLocalLog,
		[switch]$DeleteLocalLog,
		[switch]$IsBackupSrv
	)
	# ---------------------------------------------------------
	# Initialize Logging
	# ---------------------------------------------------------
	#$Script:Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
	#$Script:LocalLogFile = Join-Path $Config.OutputRoot "DeployReport_$($Script:Timestamp).log"
	
	#Wait 10 Seconds - System needs to start background services etc. after foregoing reboot.
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Generating Report:" -PercentComplete 0
	Write-Log "###        Starting Deployment Report generation."
	Start-Sleep -Seconds 10

	# ---------------------------------------------------------
	# Prepare Folders
	# ---------------------------------------------------------
	Get-Folder $($Config.LocalWorkDir)

	# ---------------------------------------------------------
	# Check OS Type
	# ---------------------------------------------------------
	Write-Log "Check OS product."
	try {
		$OSType = (Get-ComputerInfo).OsProductType
	}
	catch {
		Write-Warning "ERROR: OS Product Type could not be gathered. $_"
		Write-Log "ERROR: OS Product Type could not be gathered. $_"
	}
	if($OSType) {
		Write-Log "OS Type: $($OSType.OsProductType)"
	}
	
	# ---------------------------------------------------------
	# Create HTML File
	# ---------------------------------------------------------
	$TimeDate = Get-Date -Format "dd-MM-yyyy_HH-mm-ss"
	$HRTimeDate = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
	$HTMLFileName = "$($Config.CompName)_WDSReport_$($TimeDate).html"
	$global:HTMLFilePath = "$($ReportFolder)\$($HTMLFileName)"

	if(-Not ( Test-Path $($ReportFolder) )){
		Write-Log "Create Directory 'DeploymentReport'."
		New-Item -Path "$($Config.LocalWorkDir)" -Name "DeploymentReport" -ItemType "directory" | Out-Null
	}

	if(-Not ( Test-Path $($MediaFolder) )){
		Write-Log "Create Directory 'Media'."
		New-Item -Path "$($ReportFolder)" -Name "Media" -ItemType "directory" | Out-Null

		# Copy media assets
		try {
			Copy-Item -Path "$($ServerMedia)\*" -Destination "$($MediaFolder)" -Recurse -Force
			Write-Log "Copied Media files from DeploymentShare."
		}
		catch {
			Write-Log "ERROR: Failed to copy media from server: $_"
		}
	}

	If (-Not ( Test-Path $global:HTMLFilePath ))
	{
		
		Write-Log "Create HTML File."
		try{
			New-Item $global:HTMLFilePath -ItemType "file" | out-null
		}
		catch{
			Write-Log "ERROR: HTML File can not be created: $_"
		}
	


		Add-HtmlBlock @"
<!doctype html>
<html>
<head>
<title>Deployment Report for $($Config.CompName)</title>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="This is a Report of the configuration from the system after it was deployed."/>
<meta name="thumbnail" content=""/>
<link rel="stylesheet" href="Media/styles.css" />
</head>
<body>
<div id="main">
<div id="title">
<img id="default_logo" src="Media/$($Config.HTMLReportLogo)" alt="Report Logo">
<h1 id="title">Deployment Report for $($Config.CompName)</h1>
<table id="report-info"><tbody>
<tr><td>Report Version:</td><td>Version $($Config.Version)</td></tr>
<tr><td>Created:</td><td>$($HRTimeDate)</td></tr>
</tbody></table>
"@

		# ---------------------------------------------------------
		# Collect Data
		# ---------------------------------------------------------
		$Data = [ordered]@{
			System				= Get-SystemInfo
			UAC 				= Get-UACStatus
			TLS 				= Get-TLSStatus
			CertPadding 		= Get-CertPaddingCheck
			CipherSuites 		= Get-TLSCipherSuites
			LLMNR 				= Get-LLMNR
			WDigest 			= Get-WDigest
			LSASS 				= Get-LSASSStatus
			SMB1 				= Get-SMB1
			SMB3 				= Get-SMB3
			BuiltinAdmin 		= Get-BuiltinAdminStatus
			LocalAdminPW 		= Get-LocalAdminPWStatus
			RDP 				= Get-RDPStatus
			RDPAuth 			= Get-RDPAuth
			LocationSvc 		= Get-LocationService
			NetLocal 			= Get-NetworkLocalization
			WinRM 				= Get-WinRMStatus
			SNMP 				= Get-SNMPFeature
			RDPFirewall 		= Get-RDPFirewall
			ICMPFirewall 		= Get-ICMPFirewall
			FirewallProfiles 	= Get-WindowsFirewallStatus
			IPv6 				= Get-IPv6Status
			FirstLogon 			= Get-FirstLogonAnimation
			DelayedSwitch 		= Get-DelayedDesktopSwitch
			WSUS 				= Get-WSUS
			WSUSOptions 		= Get-WSUSOptions
			OEM 				= Get-OEMInfo
			PowerPlan 			= Get-PowerPlan
			PowerPlanConfig 	= Get-PowerPlanConfig
			Volumes 			= Get-VolumeInfo
			BitLocker 			= Get-BitLockerInfo
			VSS 				= Get-VSSStatus
			Users 				= Get-LocalUserInfo
			Groups 				= Get-LocalGroupsInfo
			Software 			= Get-InstalledSoftware
			Services 			= Get-DefaultRunningServices
			Drivers 			= Get-InstalledDrivers
		}

		if($OSType -eq "Server"){
			$Data += [ordered]@{
				RolesFeatures 		= Get-InstalledRolesFeatures
				# ---------------------------------------------------------
				# Backup Server Security Compliance
				WinScriptHost 			= Get-WinScriptHost
				NetBios					= Get-NetBios
				WinHttpProxy			= Get-WinHttpAutoProxy
				WinRMSvcStatus			= Get-WinRMSvcStatus
				RemoteRegSvcStatus		= Get-RemoteRegistry
				TermSvcStatus			= Get-TermSvcStatus
				# ---------------------------------------------------------
			}
		}

		# Convert to PSCustomObject at the end
		$Data = [PSCustomObject]$Data

		# ---------------------------------------------------------
		# Write HTML Sections
		# ---------------------------------------------------------
		Write-Log "###        Checking System Information."
		Start-Section "System Information"
		Write-SystemInfoHtml -Data $Data.System

		Add-HtmlBlock @"
	<h2>OS Security Configuration</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking UAC:" -PercentComplete 2
		Write-Log "###        Checking UAC."
		Start-Section "UAC Status"
		Write-UACHtml -Data $Data.UAC

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking TLS:" -PercentComplete 5
		Write-Log "###        Checking TLS."
		Start-Section "SSL/TLS Status"
		Write-TLSHtml -Data $Data.TLS

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking CertPaddingCheck:" -PercentComplete 7
		Write-Log "###        Checking CertPaddingCheck."
		Start-Section "CertPaddingCheck Status"
		Write-CertPadChkHtml -Data $Data.CertPadding

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking TLSCipherSuites:" -PercentComplete 9
		Write-Log "###        Checking TLSCipherSuites."
		Start-Section "TLS Cipher Suites Status"
		Write-TLSCipherSuitesHtml -Data $Data.CipherSuites

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking LLMNR:" -PercentComplete 11
		Write-Log "###        Checking LLMNR."
		Start-Section "LLMNR Status"
		Write-LLMNRHtml -Data $Data.LLMNR

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WDigest:" -PercentComplete 13
		Write-Log "###        Checking WDigest."
		Start-Section "WDigest Status"
		Write-WDigestHtml -Data $Data.WDigest

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking LSASS:" -PercentComplete 15
		Write-Log "###        Checking LSASS."
		Start-Section "LSASS Status"
		Write-LSASSHtml -Data $Data.LSASS

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SMBv1:" -PercentComplete 18
		Write-Log "###        Checking SMBv1."
		Start-Section "SMBv1 Status"
		Write-SMB1Html -Data $Data.SMB1

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SMBv3:" -PercentComplete 20
		Write-Log "###        Checking SMBv3."
		Start-Section "SMBv3 Status"
		Write-SMB3Html -Data $Data.SMB3

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Built-In Administrator:" -PercentComplete 22
		Write-Log "###        Checking Built-In Administrator."
		Start-Section "Builtin Administrator Status"
		Write-BuiltinAdminHtml -Data $Data.BuiltinAdmin

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking sysadmin:" -PercentComplete 25
		Write-Log "###        Checking Local Admin Password Settings."
		Start-Section "Local Admin Password Status"
		Write-LocalAdminPWHtml -Data $Data.LocalAdminPW

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP Status:" -PercentComplete 28
		Write-Log "###        Checking RDP Status."
		Start-Section "RDP Status"
		Write-RDPHtml -Data $Data.RDP

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP Authentication:" -PercentComplete 31
		Write-Log "###        Checking RDP Authentication."
		Start-Section "RDP Authentication Status"
		Write-RDPAuthHtml -Data $Data.RDPAuth

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Location Service:" -PercentComplete 34
		Write-Log "###        Checking Location Service."
		Start-Section "Location Service Status"
		Write-LocationSvcHtml -Data $Data.LocationSvc

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Network Localization:" -PercentComplete 37
		Write-Log "###        Checking Network Localization."
		Start-Section "Network Window Status"
		Write-NetLocalHtml -Data $Data.NetLocal

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WinRM Service:" -PercentComplete 40
		Write-Log "###        Checking WinRM."
		Start-Section "WinRM Status"
		Write-WinRMHtml -Data $Data.WinRM

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking SNMP Feature:" -PercentComplete 42
		Write-Log "###        Checking SNMP Feature."
		Start-Section "SNMP Feature Status"
		Write-SNMPHtml -Data $Data.SNMP

		# ---------------------------------------------------------
		# BACKUP SERVER SECURITY COMPLIANCE
		# ---------------------------------------------------------
		if($IsBackupSrv) {
			Add-HtmlBlock @"
    <h2>Additional Backup Server Security Compliance</h2>
"@
			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Windows Script Host:" -PercentComplete 43
			Write-Log "###        Checking Windows Script Host."
			Start-Section "Windows Script Host Status"
			Write-WinScriptHostHtml -Data $Data.WinScriptHost

			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking NetBIOS:" -PercentComplete 44
			Write-Log "###        Checking NetBIOS."
			Start-Section "NetBIOS Status"
			Write-NetBiosHtml -Data $Data.NetBios

			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WinHttpAutoProxy:" -PercentComplete 45
			Write-Log "###        Windows HTTP Auto Proxy."
			Start-Section "Windows HTTP Auto Proxy"
			Write-WinHttpProxyHtml -Data $Data.WinHttpProxy

			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WinRM Status:" -PercentComplete 46
			Write-Log "###        WinRM Service Status."
			Start-Section "WinRM Service Status"
			Write-WinRMSvcStatusHtml -Data $Data.WinRMSvcStatus

			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RemoteRegistry Status:" -PercentComplete 47
			Write-Log "###        Remote Registry Service Status."
			Start-Section "Remote Registry Service Status"
			Write-RemoteRegSvcStatusHtml -Data $Data.RemoteRegSvcStatus

			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP Status:" -PercentComplete 48
			Write-Log "###        Remote Desktop Service Status."
			Start-Section "Remote Desktop Service Status"
			Write-TermSvcStatusHtml -Data $Data.TermSvcStatus
		}

		# ---------------------------------------------------------

		Add-HtmlBlock @"
	<h2>Firewall Configuration</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking RDP in Windows Firewall:" -PercentComplete 49
		Write-Log "###        Checking RDP in Windows Firewall."
		Start-Section "RDP Firewall Rule Status"
		Write-RDPFirewallHtml -Data $Data.RDPFirewall

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking ICMP in Windows Firewall:" -PercentComplete 50
		Write-Log "###        Checking ICMP in Windows Firewall."
		Start-Section "ICMP Firewall Rule Status"
		Write-ICMPFirewallHtml -Data $Data.ICMPFirewall

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Windows Firewall:" -PercentComplete 51
		Write-Log "###        Checking Windows Firewall."
		Start-Section "Windows Firewall Profile Status"
		Write-FirewallProfilesHtml -Data $Data.FirewallProfiles

		Add-HtmlBlock @"
	<h2>OS Adjustments</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking IPv6:" -PercentComplete 54
		Write-Log "###        Checking IPv6."
		Start-Section "IPv6 NIC Status"
		Write-IPv6Html -Data $Data.IPv6

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking First Logon Animation:" -PercentComplete 57
		Write-Log "###        Checking First Logon Animation."
		Start-Section "First Logon Animation Status"
		Write-FirstLogonHtml -Data $Data.FirstLogon

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Delayed Desktop Switch:" -PercentComplete 60
		Write-Log "###        Checking Delayed Desktop Switch."
		Start-Section "First Delayed Desktop Switch Status"
		Write-DelayedSwitchHtml -Data $Data.DelayedSwitch

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WSUS Server Settings:" -PercentComplete 62
		Write-Log "###        Checking WSUS Server Settings."
		Start-Section "WSUS Server Settings"
		Write-WSUSHtml -Data $Data.WSUS

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking WSUS Options:" -PercentComplete 65
		Write-Log "###        Checking WSUS Options."
		Start-Section "WSUS Options"
		Write-WSUSOptionsHtml -Data $Data.WSUSOptions

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking OEM Info:" -PercentComplete 68
		Write-Log "###        Checking OEM Info."
		Start-Section "OEM Info"
		Write-OEMHtml -Data $Data.OEM

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking PowerPlan:" -PercentComplete 71
		Write-Log "###        Checking PowerPlan."
		Start-Section "Power Plan Info"
		Write-PowerPlanHtml -Data $Data.PowerPlan

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Power Confguration:" -PercentComplete 74
		Write-Log "###        Checking Power Confguration."
		Start-Section "Power Plan Config"
		Write-PowerPlanConfigHtml -Data $Data.PowerPlanConfig
		
		Add-HtmlBlock @"
	<h2>Storage Information</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Volume Information:" -PercentComplete 77
		Write-Log "###        Checking Volume Information."
		Start-Section "Volumes Info"
		Write-VolumesHtml -Data $Data.Volumes

		if($OSType -eq "WorkStation") {
			Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking BitLocker Information:" -PercentComplete 80
			Write-Log "###        Checking BitLocker Information."
			Start-Section "BitLocker Info"
			Write-BitLockerHtml -Data $Data.BitLocker
		}

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking VSS:" -PercentComplete 82
		Write-Log "###        Checking VSS."
		Start-Section "VSS Info"
		Write-VSSHtml -Data $Data.VSS

		Add-HtmlBlock @"
	<h2>Local User & Groups</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Local User Information:" -PercentComplete 85
		Write-Log "###        Checking Local User Information."
		Start-Section "Local User Info"
		Write-LocalUsersInfoHtml -Data $Data.Users

		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Local Group Information:" -PercentComplete 88
		Write-Log "###        Checking Local Group Information."
		Start-Section "Local Group Info"
		Write-LocalGroupsInfoHtml -Data $Data.Groups

		Add-HtmlBlock @"
	<h2>Software & Windows Features</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Installed Software:" -PercentComplete 90
		Write-Log "###        Checking Installed Software."
		Start-Section "Software Info"
		Write-SoftwareHtml -Data $Data.Software

		if($OSType -eq "Server") {
			Write-Log "###        Checking Installed Roles and Features."
			Start-Section "Roles and Features Info"
			Write-RolesFeaturesHtml -Data $Data.RolesFeatures
		}

		Add-HtmlBlock @"
	<h2>System Services</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Active Services:" -PercentComplete 93
		Write-Log "###        Checking Active Services."
		Start-Section "Running Services Info"
		Write-ServicesHtml -Data $Data.Services

		Add-HtmlBlock @"
	<h2>Installed Drivers</h2>
"@
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Checking Installed Drivers:" -PercentComplete 94
		Write-Log "###        Checking Installed Drivers."
		Start-Section "Installed Drivers Info"
		Write-DriversHtml -Data $Data.Drivers




		# ---------------------------------------------------------
		# Close HTML
		# ---------------------------------------------------------
		Add-HtmlBlock @"
</div>
</body>
</html>
"@

	


		# ---------------------------------------------------------
		# Convert to PDF
		# ---------------------------------------------------------
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Convert To PDF:" -PercentComplete 96
		Write-Log "###        Convert To PDF."
		Start-Section "Finalize: Convert HTML Report to PDF File"
		Convert-ToPDF -HtmlFile $global:HTMLFilePath


		# ---------------------------------------------------------
		# Finalize
		# ---------------------------------------------------------
		Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Flush Variables:" -PercentComplete 97
		Write-Log "###        Flush Variables."
		Start-Section "Finalize: Flush Variables"
		Flush-Variables
	}

	#---------------------------------------------------------
	# Finalizing
	#---------------------------------------------------------
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 98
	
	#---------------------------------------------------------
	# Upload local logFile
	#---------------------------------------------------------
	if($UploadLocalLog){
		Write-Log "Uploading local log file."
		try{
			Copy-Item "$localLogFile" -Destination "$logFilePath"
		}
		catch{
			Write-Warning "ERROR: Logfile '$localLogFile' could not be uploaded to Deployment-Server.
			Reason: $_"
			Write-Log "ERROR: Logfile '$localLogFile' could not be uploaded to Deployment-Server. $_"
		}
		Start-Sleep 10
	}
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 99

	#---------------------------------------------------------
	# Delete local logFile
	#---------------------------------------------------------
	if($DeleteLocalLog){
		Write-Log "Deleting local log file."
		try{
			Remove-Item "$localLogFile" -Force
		}
		catch{
			Write-Warning "ERROR: Logfile '$localLogFile' could not be deleted.
			Reason: $_"
			Write-Log "ERROR: Logfile '$localLogFile' could not be deleted. $_"
		}
		Start-Sleep 10
	}
	Write-Progress -id 1 -Activity "Generating Deployment Report" -Status "Finalizing:" -PercentComplete 100
	Write-Log "###        Finish Logging."
}

# ---------------------------------------------------------
# Entry Point
# ---------------------------------------------------------
Start-DeploymentReport #-UploadLocalLog #-DeleteLocalLog




