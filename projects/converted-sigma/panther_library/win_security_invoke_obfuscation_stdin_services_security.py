# Title: Invoke-Obfuscation STDIN+ Launcher - Security
# ID: 0c718a5e-4284-4fb9-b4d9-b9a50b3a1974
# Status: test
# Level: high
# Author: Jonathan Cheong, oscd.community
# Date: 2020-10-15
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated use of stdin to execute PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation STDIN+ Launcher - Security
def rule(event):
    # Detection Logic:
    # ((EventID="4697" AND (ServiceFileName="*cmd*" AND ServiceFileName="*powershell*")) AND ((ServiceFileName="*${input}*" OR ServiceFileName="*noexit*")) AND ((ServiceFileName="* /c *" OR ServiceFileName="* /r *")))
    return True

def title(event):
    return "Invoke-Obfuscation STDIN+ Launcher - Security"

