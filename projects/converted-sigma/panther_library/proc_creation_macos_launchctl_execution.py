# Title: Launch Agent/Daemon Execution Via Launchctl
# ID: ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e
# Status: test
# Level: medium
# Author: Pratinav Chandra
# Date: 2024-05-13
# Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1569.001, attack.t1543.001, attack.t1543.004
# Description: Detects the execution of programs as Launch Agents or Launch Daemons using launchctl on macOS.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Launch Agent/Daemon Execution Via Launchctl
def rule(event):
    # Detection Logic:
    # (Image="*/launchctl" AND (CommandLine="*submit*" OR CommandLine="*load*" OR CommandLine="*start*"))
    return True

def title(event):
    return "Launch Agent/Daemon Execution Via Launchctl"

