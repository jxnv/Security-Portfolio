# Title: JXA In-memory Execution Via OSAScript
# ID: f1408a58-0e94-4165-b80a-da9f96cf6fc3
# Status: test
# Level: high
# Author: Sohan G (D4rkCiph3r)
# Date: 2023-01-31
# Tags: attack.t1059.002, attack.t1059.007, attack.execution
# Description: Detects possible malicious execution of JXA in-memory via OSAScript
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: JXA In-memory Execution Via OSAScript
def rule(event):
    # Detection Logic:
    # ((((CommandLine="* -l *" AND CommandLine="*JavaScript*")) OR (CommandLine="*.js*")) AND ((CommandLine="*osascript*" AND CommandLine="* -e *" AND CommandLine="*eval*" AND CommandLine="*NSData.dataWithContentsOfURL*")))
    return True

def title(event):
    return "JXA In-memory Execution Via OSAScript"

