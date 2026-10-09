# Title: Renamed Vmnat.exe Execution
# ID: 7b4f794b-590a-4ad4-ba18-7964a2832205
# Status: test
# Level: high
# Author: elhoim
# Date: 2022-09-09
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
# Description: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Renamed Vmnat.exe Execution
def rule(event):
    # Detection Logic:
    # ((OriginalFileName="vmnat.exe") AND NOT ((Image="*vmnat.exe")))
    return True

def title(event):
    return "Renamed Vmnat.exe Execution"

