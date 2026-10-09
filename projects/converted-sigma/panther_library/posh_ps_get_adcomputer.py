# Title: Active Directory Computers Enumeration With Get-AdComputer
# ID: 36bed6b2-e9a0-4fff-beeb-413a92b86138
# Status: test
# Level: low
# Author: frack113
# Date: 2022-03-17
# Tags: attack.discovery, attack.t1018, attack.t1087.002
# Description: Detects usage of the "Get-AdComputer" to enumerate Computers or properties within Active Directory.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Active Directory Computers Enumeration With Get-AdComputer
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Get-AdComputer *") AND ((ScriptBlockText="*-Filter *" OR ScriptBlockText="*-LDAPFilter *" OR ScriptBlockText="*-Properties *")))
    return True

def title(event):
    return "Active Directory Computers Enumeration With Get-AdComputer"

