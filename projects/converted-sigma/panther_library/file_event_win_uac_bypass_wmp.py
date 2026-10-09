# Title: UAC Bypass Using Windows Media Player - File
# ID: 68578b43-65df-4f81-9a9b-92f32711a951
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-23
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using Windows Media Player - File
def rule(event):
    # Detection Logic:
    # ((TargetFilename="C:\\Users\\*" AND TargetFilename="*\\AppData\\Local\\Temp\\OskSupport.dll") OR (Image="C:\\Windows\\system32\\DllHost.exe" AND TargetFilename="C:\\Program Files\\Windows Media Player\\osk.exe"))
    return True

def title(event):
    return "UAC Bypass Using Windows Media Player - File"

