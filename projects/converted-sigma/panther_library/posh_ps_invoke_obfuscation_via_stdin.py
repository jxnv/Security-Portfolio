# Title: Invoke-Obfuscation Via Stdin - Powershell
# ID: 86b896ba-ffa1-4fea-83e3-ee28a4c915c7
# Status: test
# Level: high
# Author: Nikita Nazarov, oscd.community
# Date: 2020-10-12
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated Powershell via Stdin in Scripts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation Via Stdin - Powershell
def rule(event):
    # Detection Logic:
    # (ScriptBlockText=regex("(?i)(set).*&&\\s?set.*(environment|invoke|\\$\\{?input).*&&.*\""))
    return True

def title(event):
    return "Invoke-Obfuscation Via Stdin - Powershell"

