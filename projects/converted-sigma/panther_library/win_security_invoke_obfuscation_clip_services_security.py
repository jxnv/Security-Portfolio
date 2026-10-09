# Title: Invoke-Obfuscation CLIP+ Launcher - Security
# ID: 4edf51e1-cb83-4e1a-bc39-800e396068e3
# Status: test
# Level: high
# Author: Jonathan Cheong, oscd.community
# Date: 2020-10-13
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated use of Clip.exe to execute PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation CLIP+ Launcher - Security
def rule(event):
    # Detection Logic:
    # (EventID="4697" AND (ServiceFileName="*cmd*" AND ServiceFileName="*&&*" AND ServiceFileName="*clipboard]::*"))
    return True

def title(event):
    return "Invoke-Obfuscation CLIP+ Launcher - Security"

