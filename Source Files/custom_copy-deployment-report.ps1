<#
.SYNOPSIS

.DESCRIPTION
    
.LINK
    
.NOTES
          FileName: custom_copy-deployment-report.ps1
          Solution: 
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2024-04-26
          Modified: 2025-02-27

          Version - 0.1.1 - () - Finalized functional version 1.
		  Version - 0.1.2 - () - Cleanup and Error Handling
		  Version - 0.1.3 - () - Adding Logging Features
		  Version - 0.1.4 - () - Changing Net Use to New-PSDrive
          

          TODO:
		  
		
.Example
#>

function StartScript {
	
	<#
	# Get Configuration
	#>
	$config = "DeplyomentReport-Upload"
	
	<#
	# Variables that may be needed to change
	#>
	$user = "wds.usr"
	# Store the password as a SecureString (less secure)
	$securePassword = ConvertTo-SecureString "YjVloU2hdKZEyN6em5Zu" -AsPlainText -Force
	# Create a PSCredential object
	$credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword)
	$SrvIP = "192.168.121.66"
	<#
	####################################################################################################
	#>
	
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
	
	
    <#
	# Variables
	#>   
	$source = "C:\_it\DeploymentReport"
    $dest = "\\$($SrvIP)\Reports"
    $reportHTML = Get-ChildItem -Path C:\_it\DeploymentReport\*.html -Name
    $reportPDF = Get-ChildItem -Path C:\_it\DeploymentReport\*.pdf -Name
    $htmlSrcFilePath = $source+"\"+$reportHTML
    $pdfSrcFilePath = $source+"\"+$reportPDF
	$MountPoint = "U"

    #Commands
    #Wait 5 Seconds - To be sure, the report creation has finished
	Write-Log "Wait 5 Seconds - To be sure, the report creation has finished."
    Start-Sleep -Seconds 5

    # Get Service Status
	Write-Log "Get Service Status."
	try{
		#Get-Service LanmanWorkstation | Restart-Service -Force
		$LanmanSvc = get-service LanmanWorkstation
	}
	catch{
		Write-Warning "
		LanmanWorkstation Service Status could not be fetched."
		Write-Log "ERROR: LanmanWorkstation Service Status could not be fetched."
	}
	Write-Log "LanMan Service Status is '$($LanmanSvc.Status)'."
	if($LanmanSvc.Status -eq "Running")
	{
		#Write-Host "LanmanWorkstation Service is Running." -ForegroundColor Green
		
		# Restart Service
		Write-Log "Restart Service LanmanWorkstation Service."
		Get-Service LanmanWorkstation | Restart-Service -Force
	}
	elseif($LanmanSvc.Status -eq "Stopped")
	{
		# Start Service
		Write-Log "Start Service LanmanWorkstation Service."
		Get-Service LanmanWorkstation | Start-Service
	}
	
	#Wait 5 Seconds - To be sure, the report creation has finished
	Write-Log "Wait 5 Seconds - To be sure, the report creation has finished."
    Start-Sleep -Seconds 5
	
    #create moundpoint for file share
	Write-Log "Create moundpoint for file share."
	try {
		New-PSDrive -Name "$($MountPoint)" -PSProvider FileSystem -Root "$($dest)" -Credential $credential
		#Wait 5 Seconds - To be sure, the report creation has finished
		Start-Sleep -Seconds 5
	}
	catch {
		Write-Warning "File Share could not be mounted under '$($MountPoint):\'. ERROR: $_"
		Write-Log "ERROR: FileShare could not be mounted under '$($MountPoint):\'. ERROR: $_"
	}

	### HTML ###
    #check if file exists before we copy it
	Write-Log "Check if html file exists before we copy it."
    if(-Not ( Test-Path "$($MountPoint):\$reportHTML" ))
    {
		Write-Log "Copy HTML File."
		try{
			copy-item "$htmlSrcFilePath" -Destination "$($MountPoint):\"
			for ($i = 0; $i -le 100; $i=$i+10 ) {
				Write-Progress -Activity "File upload in Progress" -Status "Upload Progress $i% Complete:" -PercentComplete $i
				Start-Sleep -Milliseconds 250
			}
		}
		catch{
			Write-Warning "HTML File could not be copied to Fileshare."
			Write-Log "ERROR: HTML File could not be copied to Fileshare."
		}
        
    }
    else {
        Write-Warning "HTML Report File already exists."
		Write-Log "ERROR: HTML Report File already exists."
    }

    ### PDF ###
    #check if file exists before we copy it
	Write-Log "Check if pdf file exists before we copy it."
    if(-Not ( Test-Path "$($MountPoint):\$reportPDF" ))
    {
		Write-Log "Copy PDF File."
        try{
			copy-item "$pdfSrcFilePath" -Destination "$($MountPoint):\"
			for ($i = 0; $i -le 100; $i=$i+10 ) {
				Write-Progress -Activity "File upload in Progress" -Status "Upload Progress $i% Complete:" -PercentComplete $i
				Start-Sleep -Milliseconds 250
			}
		}
		catch{
			Write-Warning "PDF File could not be copied to Fileshare."
			Write-Log "ERROR: PDF File could not be copied to Fileshare."
		}
    }
    else {
        Write-Warning "PDF Report File already exists."
		Write-Log "ERROR: PDF Report File already exists."
    }
   
	# delete mount point
	Write-Log "Delete mount point."
	Remove-PSDrive -Name $MountPoint
	
	

    # Call Function #
	Write-Log "Flush Variables."
    FlushVariables
	
	Write-Log "Finish Logging."
	
	<#
	# Finalizing
	#>
	# Upload logFile
	try{
		Copy-Item "$localLogFile" -Destination "$logFilePath"
	}
	catch{
		Write-Warning "ERROR: Logfile '$localLogFile' could not be uploaded to Deployment-Server.
		Reason: $_"
	}

	# Delete local logFile
	try{
		Remove-Item "$localLogFile" -Force
	}
	catch{
		Write-Warning "ERROR: Logfile '$localLogFile' could not be deleted.
		Reason: $_"
	}
}

function FlushVariables {
    #Flush Variables
    $user = ""
    $pass = ""
    $source = ""
    $dest = ""
    $reportHTML = ""
    $reportPDF = ""
    $htmlSrcFilePath = ""
    $pdfSrcFilePath = ""
	$MountPoint = ""
}


### Function Calls ###
StartScript