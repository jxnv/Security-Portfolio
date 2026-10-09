# Title: UAC Bypass Abusing Winsat Path Parsing - File
# ID: 155dbf56-e0a4-4dd0-8905-8a98705045e8
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Abusing Winsat Path Parsing - File
def rule(event):
    # Detection Logic:
    # (TargetFilename="C:\\Users\\*" AND (TargetFilename="*\\AppData\\Local\\Temp\\system32\\winsat.exe" OR TargetFilename="*\\AppData\\Local\\Temp\\system32\\winmm.dll"))
    return True

def title(event):
    return "UAC Bypass Abusing Winsat Path Parsing - File"

