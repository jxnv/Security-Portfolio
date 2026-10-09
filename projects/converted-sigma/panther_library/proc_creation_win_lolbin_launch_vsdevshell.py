# Title: Launch-VsDevShell.PS1 Proxy Execution
# ID: 45d3a03d-f441-458c-8883-df101a3bb146
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-19
# Tags: attack.stealth, attack.t1216.001
# Description: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Launch-VsDevShell.PS1 Proxy Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="*VsWherePath *" OR CommandLine="*VsInstallationPath *")) AND (CommandLine="*Launch-VsDevShell.ps1*"))
    return True

def title(event):
    return "Launch-VsDevShell.PS1 Proxy Execution"

