# Title: UAC Bypass Using MSConfig Token Modification - File
# ID: 41bb431f-56d8-4691-bb56-ed34e390906f
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using MSConfig Token Modification - File
def rule(event):
    # Detection Logic:
    # (TargetFilename="C:\\Users\\*" AND TargetFilename="*\\AppData\\Local\\Temp\\pkgmgr.exe")
    return True

def title(event):
    return "UAC Bypass Using MSConfig Token Modification - File"

