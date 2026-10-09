# Title: Suspicious Query of MachineGUID
# ID: f5240972-3938-4e56-8e4b-e33893176c1f
# Status: test
# Level: low
# Author: frack113
# Date: 2022-01-01
# Tags: attack.discovery, attack.t1082
# Description: Use of reg to get MachineGuid information
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Query of MachineGUID
def rule(event):
    # Detection Logic:
    # (Image="*\\reg.exe" AND (CommandLine="*SOFTWARE\\Microsoft\\Cryptography*" AND CommandLine="*/v *" AND CommandLine="*MachineGuid*"))
    return True

def title(event):
    return "Suspicious Query of MachineGUID"

