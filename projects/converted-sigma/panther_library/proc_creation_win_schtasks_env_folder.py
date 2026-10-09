# Title: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
# ID: 81325ce1-be01-4250-944f-b4789644556f
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2022-02-21
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
# Description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
def rule(event):
    # Detection Logic:
    # (((((CommandLine="*:\\Perflogs*" OR CommandLine="*:\\Users\\All Users\\*" OR CommandLine="*:\\Users\\Default\\*" OR CommandLine="*:\\Users\\Public*" OR CommandLine="*:\\Windows\\Temp*" OR CommandLine="*\\AppData\\Local\\*" OR CommandLine="*\\AppData\\Roaming\\*" OR CommandLine="*%AppData%*" OR CommandLine="*%Public%*")) AND (Image="*\\schtasks.exe" AND CommandLine="* /create *")) OR ((ParentCommandLine="*\\svchost.exe -k netsvcs -p -s Schedule") AND ((CommandLine="*:\\Perflogs*" OR CommandLine="*:\\Windows\\Temp*" OR CommandLine="*\\Users\\Public*" OR CommandLine="*%Public%*")))) AND NOT ((((CommandLine="*/Create /Xml *" AND CommandLine="*\\Temp\\.CR.*" AND CommandLine="*\\Avira_Security_Installation.xml*")) OR ((CommandLine="*/Create /F /TN*" AND CommandLine="*/Xml *" AND CommandLine="*\\Temp\\*" AND CommandLine="*Avira_*") AND (CommandLine="*.tmp\\UpdateFallbackTask.xml*" OR CommandLine="*.tmp\\WatchdogServiceControlManagerTimeout.xml*" OR CommandLine="*.tmp\\SystrayAutostart.xml*" OR CommandLine="*.tmp\\MaintenanceTask.xml*")) OR ((CommandLine="*\\Temp\\*" AND CommandLine="*/Create /TN \"klcp_update\" /XML *" AND CommandLine="*\\klcp_update_task.xml*")) OR ((ParentCommandLine="*unattended.ini*") OR (CommandLine="*update_task.xml*")) OR (CommandLine="*/Create /TN TVInstallRestore /TR*"))))
    return True

def title(event):
    return "Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE"

