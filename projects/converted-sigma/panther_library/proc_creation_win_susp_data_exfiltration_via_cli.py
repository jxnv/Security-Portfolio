# Title: Potential Data Exfiltration Activity Via CommandLine Tools
# ID: 7d1aaf3d-4304-425c-b7c3-162055e0b3ab
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-02
# Tags: attack.execution, attack.t1059.001
# Description: Detects the use of various CLI utilities exfiltrating data via web requests
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Data Exfiltration Activity Via CommandLine Tools
def rule(event):
    # Detection Logic:
    # ((((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe") AND (CommandLine="*curl *" OR CommandLine="*Invoke-RestMethod*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*irm *" OR CommandLine="*iwr *" OR CommandLine="*wget *") AND (CommandLine="* -ur*" AND CommandLine="* -me*" AND CommandLine="* -b*" AND CommandLine="* POST *")) OR ((Image="*\\curl.exe" AND CommandLine="*--ur*") AND ((CommandLine="* -d *" OR CommandLine="* --data *"))) OR (Image="*\\wget.exe" AND (CommandLine="*--post-data*" OR CommandLine="*--post-file*"))) AND (((CommandLine=regex("net\\s+view") OR CommandLine=regex("sc\\s+query"))) OR ((CommandLine="*Get-Content*" OR CommandLine="*GetBytes*" OR CommandLine="*hostname*" OR CommandLine="*ifconfig*" OR CommandLine="*ipconfig*" OR CommandLine="*netstat*" OR CommandLine="*nltest*" OR CommandLine="*qprocess*" OR CommandLine="*systeminfo*" OR CommandLine="*tasklist*" OR CommandLine="*ToBase64String*" OR CommandLine="*whoami*")) OR ((CommandLine="*type *" AND CommandLine="* > *" AND CommandLine="* C:\\*"))))
    return True

def title(event):
    return "Potential Data Exfiltration Activity Via CommandLine Tools"

