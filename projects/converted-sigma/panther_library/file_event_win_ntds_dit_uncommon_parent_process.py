# Title: NTDS.DIT Creation By Uncommon Parent Process
# ID: 4e7050dd-e548-483f-b7d6-527ab4fa784d
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-03-11
# Tags: attack.credential-access, attack.t1003.003
# Description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: NTDS.DIT Creation By Uncommon Parent Process
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*\\ntds.dit") AND (((ParentImage="*\\cscript.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\wscript.exe")) OR ((ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\AppData\\*" OR ParentImage="*\\Temp\\*" OR ParentImage="*\\Public\\*" OR ParentImage="*\\PerfLogs\\*"))))
    return True

def title(event):
    return "NTDS.DIT Creation By Uncommon Parent Process"

