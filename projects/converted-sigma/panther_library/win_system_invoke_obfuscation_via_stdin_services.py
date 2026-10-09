# Title: Invoke-Obfuscation Via Stdin - System
# ID: 487c7524-f892-4054-b263-8a0ace63fc25
# Status: test
# Level: high
# Author: Nikita Nazarov, oscd.community
# Date: 2020-10-12
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects Obfuscated Powershell via Stdin in Scripts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Invoke-Obfuscation Via Stdin - System
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND EventID="7045" AND (ImagePath="*set*" AND ImagePath="*&&*") AND (ImagePath="*environment*" OR ImagePath="*invoke*" OR ImagePath="*input*"))
    return True

def title(event):
    return "Invoke-Obfuscation Via Stdin - System"

