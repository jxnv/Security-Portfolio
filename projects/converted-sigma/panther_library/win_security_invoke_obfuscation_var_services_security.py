# Title: Invoke-Obfuscation VAR+ Launcher - Security
# ID: dcf2db1f-f091-425b-a821-c05875b8925a
# Status: test
# Level: high
# Author: Jonathan Cheong, oscd.community
# Date: 2020-10-15
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated use of Environment Variables to execute PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation VAR+ Launcher - Security
def rule(event):
    # Detection Logic:
    # (EventID="4697" AND (ServiceFileName="*cmd*" AND ServiceFileName="*\"set*" AND ServiceFileName="*-f*") AND (ServiceFileName="*/c*" OR ServiceFileName="*/r*"))
    return True

def title(event):
    return "Invoke-Obfuscation VAR+ Launcher - Security"

