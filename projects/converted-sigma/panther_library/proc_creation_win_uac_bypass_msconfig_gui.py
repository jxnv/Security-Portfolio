# Title: UAC Bypass Using MSConfig Token Modification - Process
# ID: ad92e3f9-7eb6-460e-96b1-582b0ccbb980
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using MSConfig Token Modification - Process
def rule(event):
    # Detection Logic:
    # ((IntegrityLevel="High" OR IntegrityLevel="System" OR IntegrityLevel="S-1-16-16384" OR IntegrityLevel="S-1-16-12288") AND ParentImage="*\\AppData\\Local\\Temp\\pkgmgr.exe" AND CommandLine="\"C:\\Windows\\system32\\msconfig.exe\" -5")
    return True

def title(event):
    return "UAC Bypass Using MSConfig Token Modification - Process"

