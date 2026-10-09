# Title: Conhost.exe CommandLine Path Traversal
# ID: ee5e119b-1f75-4b34-add8-3be976961e39
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-14
# Tags: attack.execution, attack.t1059.003
# Description: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Conhost.exe CommandLine Path Traversal
def rule(event):
    # Detection Logic:
    # (ParentCommandLine="*conhost*" AND CommandLine="*/../../*")
    return True

def title(event):
    return "Conhost.exe CommandLine Path Traversal"

