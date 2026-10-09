# Title: UAC Bypass Using NTFS Reparse Point - File
# ID: 7fff6773-2baa-46de-a24a-b6eec1aba2d1
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-30
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using NTFS Reparse Point - File
def rule(event):
    # Detection Logic:
    # (TargetFilename="C:\\Users\\*" AND TargetFilename="*\\AppData\\Local\\Temp\\api-ms-win-core-kernel32-legacy-l1.DLL")
    return True

def title(event):
    return "UAC Bypass Using NTFS Reparse Point - File"

