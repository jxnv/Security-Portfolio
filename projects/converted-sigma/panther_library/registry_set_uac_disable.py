# Title: UAC Disabled
# ID: 48437c39-9e5f-47fb-af95-3d663c3f2919
# Status: stable
# Level: medium
# Author: frack113
# Date: 2022-01-05
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects when an attacker tries to disable User Account Control (UAC) by setting the registry value "EnableLUA" to 0.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Disabled
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA*" AND Details="DWORD (0x00000000)")
    return True

def title(event):
    return "UAC Disabled"

