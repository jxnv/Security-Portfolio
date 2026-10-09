# Title: Powershell Suspicious Win32_PnPEntity
# ID: b26647de-4feb-4283-af6b-6117661283c5
# Status: test
# Level: low
# Author: frack113
# Date: 2021-08-23
# Tags: attack.discovery, attack.t1120
# Description: Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Suspicious Win32_PnPEntity
def rule(event):
    # Detection Logic:
    # (ScriptBlockText="*Win32_PnPEntity*")
    return True

def title(event):
    return "Powershell Suspicious Win32_PnPEntity"

