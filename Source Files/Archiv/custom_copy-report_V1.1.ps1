<#
.SYNOPSIS

.DESCRIPTION
    
.LINK
    
.NOTES
          FileName: custom_copy-report_V1.1.ps1
          Solution: 
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 
          Modified: 2024-10-30

          Version - 0.1.1 - () - Finalized functional version 1.
		  Version - 0.1.2 - () - Adapting for PSD
          

          TODO:
		  
		
.Example
#>

function StartScript {
    #Variables
    $user = "wds.usr"
    $pass = "o8yN.EC62ed-Y5h!x_X"
    $source = "C:\_it\DeploymentReport"
    $dest = "\\192.168.121.67\Reports"
    $reportHTML = Get-ChildItem -Path C:\_it\DeploymentReport\*.html -Name
    $reportPDF = Get-ChildItem -Path C:\_it\DeploymentReport\*.pdf -Name
    $htmlSrcFilePath = $source+"\"+$reportHTML
    $pdfSrcFilePath = $source+"\"+$reportPDF
	$MountPoint = "u:"
<#
    $getHTMLFile = Get-Item $htmlSrcFilePath
    $htmlFileSize = $getHTMLFile.Length
    $getPDFFile = Get-Item $pdfSrcFilePath
    $pdfFileSize = $getPDFFile.Length
    

    write-host $source
    write-host $dest
    write-host $reportHTML
    write-host $reportPDF
    Write-Host $htmlSrcFilePath
    write-host "$reportHTML is $htmlFileSize Bytes"
    Write-Host $pdfSrcFilePath
    write-host "$reportPDF is $pdfFileSize Bytes"
    #>

    #Commands
    #Wait 5 Seconds - To be sure, the report creation has finished
    Start-Sleep -Seconds 5

    Get-Service LanmanWorkstation | Restart-Service -Force
	
	#Wait 5 Seconds - To be sure, the report creation has finished
    Start-Sleep -Seconds 5
	
    #create moundpoint for file share
	try {
		net use $MountPoint $dest $pass /user:$user /persistent:no
		#Wait 5 Seconds - To be sure, the report creation has finished
		Start-Sleep -Seconds 5
	}
	catch {
		Write-Host "File Share could not be mounted under '$MountPoint\'."
	}

	### HTML ###
    #check if file exists before we copy it
    if(-Not ( Test-Path "$MountPoint\$reportHTML" ))
    {
        copy-item "$htmlSrcFilePath" -Destination "$MountPoint\"
        for ($i = 0; $i -le 100; $i=$i+10 ) {
            Write-Progress -Activity "File Copy in Progress" -Status "Copy Progress $i% Complete:" -PercentComplete $i
            Start-Sleep -Milliseconds 250
        }
        
    }
    else {
        Write-Host "HTML File already exists." -ForegroundColor Yellow
    }

    ### PDF ###
    #check if file exists before we copy it
    if(-Not ( Test-Path "$MountPoint\$reportPDF" ))
    {
        copy-item "$pdfSrcFilePath" -Destination "$MountPoint\"
        for ($i = 0; $i -le 100; $i=$i+10 ) {
            Write-Progress -Activity "File Copy in Progress" -Status "Copy Progress $i% Complete:" -PercentComplete $i
            Start-Sleep -Milliseconds 250
        }
    }
    else {
        Write-Host "PDF File already exists." -ForegroundColor Yellow
    }
   
	# delete mount point
    net use $MountPoint /delete

    # Call Function #
    FlushVariables
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