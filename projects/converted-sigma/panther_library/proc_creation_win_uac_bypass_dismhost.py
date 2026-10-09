# Title: UAC Bypass Using DismHost
# ID: 853e74f9-9392-4935-ad3b-2e8c040dae86
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using DismHost
def rule(event):
    # Detection Logic:
    # ((ParentImage="*C:\\Users\\*" AND ParentImage="*\\AppData\\Local\\Temp\\*" AND ParentImage="*\\DismHost.exe*") AND (IntegrityLevel="High" OR IntegrityLevel="System" OR IntegrityLevel="S-1-16-16384" OR IntegrityLevel="S-1-16-12288"))
    return True

def title(event):
    return "UAC Bypass Using DismHost"

