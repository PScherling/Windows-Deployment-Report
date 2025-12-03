<#
.SYNOPSIS
	Copies the generated deployment report (HTML + PDF) from the local machine to a central file share with logging, progress, and basic resilience.
.DESCRIPTION
    This script is intended to run after a deployment report has been created under C:\_psc\DeploymentReport. It:
	- Initializes logging to C:\_psc and uploads the log to \\$SrvIP\Logs$\Custom\Configuration.
	- Verifies the LanmanWorkstation service is available (restarts/starts if needed).
	- Mounts the reports share (\\$SrvIP\Reports) via New-PSDrive using supplied credentials.
	- Detects the newest report files (*.html, *.pdf) in C:\_psc\DeploymentReport.
	- Copies each file to the mounted share if a file with the same name is not already present.
	- Shows copy progress, then removes the temporary PSDrive.
	- Flushes sensitive variables, uploads the execution log, and deletes the local log.
.LINK
    https://learn.microsoft.com/powershell/module/microsoft.powershell.management/new-psdrive
	https://learn.microsoft.com/windows-server/administration/windows-commands/sc
	https://learn.microsoft.com/powershell/module/microsoft.powershell.management/copy-item
	https://github.com/PScherling

.NOTES
          FileName: custom_copy-deployment-report.ps1
          Solution: Post-deployment artifact collection and centralization.
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2024-04-26
          Modified: 2025-12-02

          Version - 0.1.1 - () - Finalized functional version 1.
		  Version - 0.1.2 - () - Cleanup and Error Handling
		  Version - 0.1.3 - () - Adding Logging Features
		  Version - 0.1.4 - () - Changing Net Use to New-PSDrive
		  Version - 0.2.0 - () - Reorganize the script to make it more accessible for adaptions
          

          TODO:

.REQUIREMENTS
	- Run in an elevated PowerShell session.
	- Network connectivity to \\$SrvIP\Reports and \\$SrvIP\Logs$ with valid credentials.
	- PowerShell 5.1+ and permission to create/remove PSDrives.

.OUTPUTS
	- Report files copied to \\$SrvIP\Reports.
	- Execution log saved to \\$SrvIP\Logs$\Custom\Configuration.
	- (Console) Progress indicators and warnings/errors.
		
.Example
	Run after the report generator finished:
	.\custom_copy-deployment-report.ps1

	If execution policy blocks the script:
	powershell -ExecutionPolicy Bypass -File .\custom_copy-deployment-report.ps1
#>


<#
#### Section 1 - Configuration Block | adapt if needed
#>
$Config = @{
	Name 					= "DeplyomentReport-Upload"
    MDTServerIP        		= "0.0.0.0"
    MountDriveLetter   		= "U"
    Username           		= "wdsuser"
    PasswordPlain      		= "Password"   #secure mechanism later
	CompName 				= $env:COMPUTERNAME
	LocalFilePath 			= "C:\_psc"
}


# Build paths
$DateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFileName = "Configure_$($Config.Name)_$($Config.CompName)_$($DateTime).log"

$logFilePath = "\\$($Config.MDTServerIP)\Logs$\Custom\Configuration"
$logFile = "$($logFilePath)\$($logFileName)"
$localLogFile = "$($Config.LocalFilePath)\$($logFileName)"

$localReportDir = "$($Config.LocalFilePath)\DeploymentReport"
$shareReportDir = "\\$($Config.MDTServerIP)\Reports"


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
# Mount Share
# ---------------------------------------------
function Mount-ReportShare {
    Write-Log "Mounting report share '$($Config.MountDriveLetter):\'."
    try {
        New-PSDrive -Name "$($Config.MountDriveLetter)" -Scope Global -PSProvider FileSystem -Root "$($shareReportDir)" -Credential $script:Credentials -ErrorAction Stop
        Start-Sleep 5
    }
    catch {
        Write-Log "ERROR: Could not mount report share. $_"
        throw
    }
}

# ---------------------------------------------
# Copy Files
# ---------------------------------------------
function Copy-ReportFile {
    param($FileName)

    $source = Join-Path $($localReportDir) $FileName
    $destination = "$($Config.MountDriveLetter):\$FileName"

    if (-not (Test-Path $destination)) {
        Write-Log "Copying '$FileName' to server."
		Write-Log "Source : $($source)"
		Write-Log "Destination: $($destination)"
        try {
            Copy-Item $source -Destination "$($Config.MountDriveLetter):\" -ErrorAction Stop

            # fake progress animation
            for ($i = 0; $i -le 100; $i=$i+10 ) {
				Write-Progress -Activity "File upload in Progress" -Status "Upload Progress $i% Complete:" -PercentComplete $i
				Start-Sleep -Milliseconds 250
			}
        }
        catch {
            Write-Log "ERROR: Could not copy '$FileName'. $_"
        }
    }
    else {
        Write-Log "WARNING: '$FileName' already exists on server. Skipping."
    }
}

# ---------------------------------------------
# Flush Variables
# ---------------------------------------------
function Flush-Variables {
    $Config.PasswordPlain = $null
    $script:Credentials   = $null
    $script:LocalLogFile  = $null
}


<#
### Section 3 - Run Upload
#>
function Start-Upload {
    # Create log + credentials
    $script:Credentials = New-Object pscredential ($Config.Username, (ConvertTo-SecureString $Config.PasswordPlain -AsPlainText -Force))

    Write-Log "==== Starting Report Upload ===="
    Write-Log "Computer Name: $CompName"

    # Ensure LanmanWorkstation is running
    Write-Log "Checking LanmanWorkstation service."
    $svc = Get-Service LanmanWorkstation
    if ($svc.Status -eq 'Stopped') {
        Write-Log "Starting LanmanWorkstation service."
        Start-Service LanmanWorkstation
    }
    elseif ($svc.Status -eq 'Running') {
        Write-Log "Restarting LanmanWorkstation service."
        Restart-Service LanmanWorkstation -Force
    }

    Start-Sleep 3

    # Mount report share
    Mount-ReportShare

    # Collect report files
    $Reports = Get-ChildItem -Path "$($localReportDir)\*" -Include *.html,*.pdf -Name

    foreach ($file in $Reports) {
        Copy-ReportFile -FileName $file
    }

    # Unmount share
    #Write-Log "Unmounting PSDrive."
    #Remove-PSDrive -Name $Config.MountDriveLetter -ErrorAction SilentlyContinue

    # Upload local log file
    Write-Log "Uploading execution log."
    try {
        Copy-Item $LocalLogFile -Destination $RemoteLogFile -ErrorAction Stop
    }
    catch {
        Write-Log "ERROR: Could not upload log. $_"
    }

    # Delete local log file
    Write-Log "Deleting local execution log."
    Remove-Item $LocalLogFile -Force -ErrorAction SilentlyContinue

    Flush-Variables
}

# Entry point
Start-Upload
Start-Upload



