# Title: Suspicious PowerShell Parent Process
# ID: 754ed792-634f-40ae-b3bc-e0448d33f695
# Status: test
# Level: high
# Author: Teymur Kheirkhabarov, Harish Segar
# Date: 2020-03-20
# Tags: attack.execution, attack.t1059.001
# Description: Detects a suspicious or uncommon parent processes of PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Parent Process
def rule(event):
    # Detection Logic:
    # (((ParentImage="*tomcat*") OR ((ParentImage="*\\amigo.exe" OR ParentImage="*\\browser.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\iexplore.exe" OR ParentImage="*\\jbosssvc.exe" OR ParentImage="*\\microsoftedge.exe" OR ParentImage="*\\microsoftedgecp.exe" OR ParentImage="*\\MicrosoftEdgeSH.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\safari.exe" OR ParentImage="*\\services.exe" OR ParentImage="*\\sqlagent.exe" OR ParentImage="*\\sqlserver.exe" OR ParentImage="*\\sqlservr.exe" OR ParentImage="*\\vivaldi.exe" OR ParentImage="*\\w3wp.exe"))) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((CommandLine="*/c powershell*" OR CommandLine="*/c pwsh*")) OR (Description="Windows PowerShell") OR (Product="PowerShell Core 6") OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))))
    return True

def title(event):
    return "Suspicious PowerShell Parent Process"

