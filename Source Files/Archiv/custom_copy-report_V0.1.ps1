# 24.04.2024
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
################ Deployment Report PowerShell Script ####################### 
## This Script copies the deployment report from deployed pc to our share ## 
##																		  ## 
##                                                                    	  ## 
##																		  ## 
############################################################################ 

#Variables
$user = "wds"
$pass = "Wds_install1!" #| ConvertTo-SecureString -AsPlainText -Force
#$cred = new-object System.Management.Automation.PsCredential($user,$pass)
$source = "C:\_it\DeploymentReport"
$dest = "\\192.168.121.62\Reports"

#Commands

#Wait 5 Seconds - To be sure, the report creation has finished
Start-Sleep -Seconds 5

Get-Service LanmanWorkstation | Restart-Service -Force

#Start-Sleep -Seconds 5

#Copy Report
#new-psdrive -name Z -Root $dest -Credential $cred -PSProvider filesystem
net use u: $dest $pass /user:$user /persistent:no

copy-item "$source\*.html" -Destination u:\

start-sleep -Seconds 5

#Remove-PSDrive Z
net use u: /delete