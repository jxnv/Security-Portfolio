# Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell
# ID: e54f5149-6ba3-49cf-b153-070d24679126
# Status: test
# Level: high
# Author: Timur Zinniatullin, oscd.community
# Date: 2020-10-13
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell
def rule(event):
    # Detection Logic:
    # (ScriptBlockText=regex("(?i)&&set.*(\\{\\d\\}){2,}\\\\\"\\s+?-f.*&&.*cmd.*/c"))
    return True

def title(event):
    return "Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell"

