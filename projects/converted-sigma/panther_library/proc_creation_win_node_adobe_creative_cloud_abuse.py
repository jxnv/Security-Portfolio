# Title: Node Process Executions
# ID: df1f26d3-bea7-4700-9ea2-ad3e990cf90e
# Status: test
# Level: medium
# Author: Max Altgelt (Nextron Systems)
# Date: 2022-04-06
# Tags: attack.execution, attack.stealth, attack.t1127, attack.t1059.007
# Description: Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Node Process Executions
def rule(event):
    # Detection Logic:
    # ((Image="*\\Adobe Creative Cloud Experience\\libs\\node.exe") AND NOT ((CommandLine="*Adobe Creative Cloud Experience\\js*")))
    return True

def title(event):
    return "Node Process Executions"

