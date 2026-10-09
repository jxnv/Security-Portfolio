# Title: Suspicious PowerShell Download - PoshModule
# ID: de41232e-12e8-49fa-86bc-c05c7e722df9
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2017-03-05
# Tags: attack.execution, attack.t1059.001
# Description: Detects suspicious PowerShell download command
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Download - PoshModule
def rule(event):
    # Detection Logic:
    # (((ContextInfo="*.DownloadFile(*" OR ContextInfo="*.DownloadString(*")) AND (ContextInfo="*System.Net.WebClient*"))
    return True

def title(event):
    return "Suspicious PowerShell Download - PoshModule"

