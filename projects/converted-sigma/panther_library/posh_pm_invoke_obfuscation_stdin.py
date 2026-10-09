# Title: Invoke-Obfuscation STDIN+ Launcher - PowerShell Module
# ID: 9ac8b09b-45de-4a07-9da1-0de8c09304a3
# Status: test
# Level: high
# Author: Jonathan Cheong, oscd.community
# Date: 2020-10-15
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated use of stdin to execute PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation STDIN+ Launcher - PowerShell Module
def rule(event):
    # Detection Logic:
    # (Payload=regex("cmd.{0,5}(?:/c|/r).+powershell.+(?:\\$\\{?input\\}?|noexit).+\""))
    return True

def title(event):
    return "Invoke-Obfuscation STDIN+ Launcher - PowerShell Module"

