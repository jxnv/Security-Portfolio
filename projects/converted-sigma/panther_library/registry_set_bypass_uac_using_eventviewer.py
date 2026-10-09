# Title: Bypass UAC Using Event Viewer
# ID: 674202d0-b22a-4af4-ae5f-2eda1f3da1af
# Status: test
# Level: high
# Author: frack113
# Date: 2022-01-05
# Tags: attack.privilege-escalation, attack.persistence, attack.t1547.010
# Description: Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Bypass UAC Using Event Viewer
def rule(event):
    # Detection Logic:
    # ((TargetObject="*_Classes\\mscfile\\shell\\open\\command\\(Default)") AND NOT ((Details="%SystemRoot%\\system32\\mmc.exe \"%1\" %*")))
    return True

def title(event):
    return "Bypass UAC Using Event Viewer"

