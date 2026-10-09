# Title: PUA - RunXCmd Execution
# ID: 93199800-b52a-4dec-b762-75212c196542
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-01-24
# Tags: attack.execution, attack.t1569.002, attack.s0029
# Description: Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - RunXCmd Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="* /account=system *" OR CommandLine="* /account=ti *")) AND (CommandLine="*/exec=*"))
    return True

def title(event):
    return "PUA - RunXCmd Execution"

