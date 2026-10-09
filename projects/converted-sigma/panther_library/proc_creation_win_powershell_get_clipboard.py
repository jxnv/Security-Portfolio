# Title: PowerShell Get-Clipboard Cmdlet Via CLI
# ID: b9aeac14-2ffd-4ad3-b967-1354a4e628c3
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2020-05-02
# Tags: attack.collection, attack.t1115
# Description: Detects usage of the 'Get-Clipboard' cmdlet via CLI
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Get-Clipboard Cmdlet Via CLI
def rule(event):
    # Detection Logic:
    # (CommandLine="*Get-Clipboard*")
    return True

def title(event):
    return "PowerShell Get-Clipboard Cmdlet Via CLI"

