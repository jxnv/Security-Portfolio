# Title: Potential Arbitrary Code Execution Via Node.EXE
# ID: 6640f31c-01ad-49b5-beb5-83498a5cd8bd
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-09
# Tags: attack.execution, attack.stealth, attack.t1127
# Description: Detects the execution node.exe which is shipped with multiple software such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Arbitrary Code Execution Via Node.EXE
def rule(event):
    # Detection Logic:
    # ((Image="*\\node.exe" AND (CommandLine="* -e *" OR CommandLine="* --eval *")) AND ((CommandLine="*.exec(*" AND CommandLine="*net.socket*" AND CommandLine="*.connect*" AND CommandLine="*child_process*")))
    return True

def title(event):
    return "Potential Arbitrary Code Execution Via Node.EXE"

