# 26.04.2024
# pscherling@eurofunk.com
# 
#
# Version 1.0
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
$pass = "Wds_install1!"
$source = "C:\_it\DeploymentReport"
$dest = "\\192.168.121.62\Reports"


#Commands
#Wait 5 Seconds - To be sure, the report creation has finished
Start-Sleep -Seconds 5

Get-Service LanmanWorkstation | Restart-Service -Force

#Copy Report
net use u: $dest $pass /user:$user /persistent:no

copy-item "$source\*.html" -Destination u:\
#To ensure, the files are copied to the share
start-sleep -Seconds 10


copy-item "$source\*.pdf" -Destination u:\
#To ensure, the files are copied to the share
start-sleep -Seconds 20

net use u: /delete