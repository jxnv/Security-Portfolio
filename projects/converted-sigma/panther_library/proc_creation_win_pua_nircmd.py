# Title: PUA - NirCmd Execution
# ID: 4e2ed651-1906-4a59-a78a-18220fca1b22
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-01-24
# Tags: attack.execution, attack.t1569.002, attack.s0029
# Description: Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - NirCmd Execution
def rule(event):
    # Detection Logic:
    # ((((CommandLine="* execmd *" OR CommandLine="*.exe script *" OR CommandLine="*.exe shexec *" OR CommandLine="* runinteractive *")) OR ((Image="*\\NirCmd.exe") OR (OriginalFileName="NirCmd.exe"))) OR (((CommandLine="* exec *" OR CommandLine="* exec2 *")) AND ((CommandLine="* show *" OR CommandLine="* hide *"))))
    return True

def title(event):
    return "PUA - NirCmd Execution"

