# Title: Windows Credential Editor Registry
# ID: a6b33c02-8305-488f-8585-03cb2a7763f2
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2019-12-31
# Tags: attack.credential-access, attack.t1003.001, attack.s0005
# Description: Detects the use of Windows Credential Editor (WCE)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Credential Editor Registry
def rule(event):
    # Detection Logic:
    # (TargetObject="*Services\\WCESERVICE\\Start*")
    return True

def title(event):
    return "Windows Credential Editor Registry"

