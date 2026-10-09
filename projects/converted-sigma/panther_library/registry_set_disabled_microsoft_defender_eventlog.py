# Title: Disabled Windows Defender Eventlog
# ID: fcddca7c-b9c0-4ddf-98da-e1e2d18b0157
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-07-04
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects the disabling of the Windows Defender eventlog as seen in relation to Lockbit 3.0 infections
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Disabled Windows Defender Eventlog
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/Operational\\Enabled*" AND Details="DWORD (0x00000000)")
    return True

def title(event):
    return "Disabled Windows Defender Eventlog"

