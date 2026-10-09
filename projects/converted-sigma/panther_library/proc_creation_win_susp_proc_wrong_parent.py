# Title: Windows Processes Suspicious Parent Directory
# ID: 96036718-71cc-4027-a538-d1587e0006a7
# Status: test
# Level: low
# Author: vburov
# Date: 2019-02-23
# Tags: attack.stealth, attack.t1036.003, attack.t1036.005
# Description: Detect suspicious parent processes of well-known Windows processes
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Processes Suspicious Parent Directory
def rule(event):
    # Detection Logic:
    # (((Image="*\\svchost.exe" OR Image="*\\taskhost.exe" OR Image="*\\lsm.exe" OR Image="*\\lsass.exe" OR Image="*\\services.exe" OR Image="*\\lsaiso.exe" OR Image="*\\csrss.exe" OR Image="*\\wininit.exe" OR Image="*\\winlogon.exe")) AND NOT ((((ParentImage="*\\Windows Defender\\*" OR ParentImage="*\\Microsoft Security Client\\*") AND ParentImage="*\\MsMpEng.exe") OR ((NOT ParentImage=*) OR ((ParentImage="" OR ParentImage="-"))) OR (((ParentImage="*\\SavService.exe" OR ParentImage="*\\ngen.exe")) OR ((ParentImage="*\\System32\\*" OR ParentImage="*\\SysWOW64\\*"))))))
    return True

def title(event):
    return "Windows Processes Suspicious Parent Directory"

