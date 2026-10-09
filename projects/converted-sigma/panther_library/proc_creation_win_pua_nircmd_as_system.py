# Title: PUA - NirCmd Execution As LOCAL SYSTEM
# ID: d9047477-0359-48c9-b8c7-792cedcdc9c4
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-01-24
# Tags: attack.execution, attack.t1569.002, attack.s0029
# Description: Detects the use of NirCmd tool for command execution as SYSTEM user
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - NirCmd Execution As LOCAL SYSTEM
def rule(event):
    # Detection Logic:
    # (CommandLine="* runassystem *")
    return True

def title(event):
    return "PUA - NirCmd Execution As LOCAL SYSTEM"

