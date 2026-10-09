# Title: Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
# ID: 7aa4e81a-a65c-4e10-9f81-b200eb229d7d
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-14
# Tags: attack.execution, attack.persistence, attack.t1059
# Description: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script to run for a specific VM state
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
def rule(event):
    # Detection Logic:
    # (((CommandLine="* script *" AND CommandLine="* set *")) AND ((Image="*\\VMwareToolBoxCmd.exe") OR (OriginalFileName="toolbox-cmd.exe")))
    return True

def title(event):
    return "Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script"

