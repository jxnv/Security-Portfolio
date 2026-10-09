# Title: UAC Bypass Using IEInstal - File
# ID: bdd8157d-8e85-4397-bb82-f06cc9c71dbb
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using IEInstal - File
def rule(event):
    # Detection Logic:
    # (Image="C:\\Program Files\\Internet Explorer\\IEInstal.exe" AND TargetFilename="C:\\Users\\*" AND TargetFilename="*\\AppData\\Local\\Temp\\*" AND TargetFilename="*consent.exe")
    return True

def title(event):
    return "UAC Bypass Using IEInstal - File"

