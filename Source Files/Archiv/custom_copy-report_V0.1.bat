:: This is an alternative to the current copy powershell script for the deployment reports.
:: Integrate this bat file as an application in MDT and Run this single Install Applicatopn in the task sequence

@echo off
set source = C:\_it\DeploymentReport\*.html
set dest = \\192.168.121.62\Reports
set user = wds
set pass = Wds_install1!

net use u: /delete
net use u: %dest% %pass% /user:%user% /persistent:no
::xcopy %source% u: /y /f
copy %source% u: /y
net use u: /delete
exit /b 0