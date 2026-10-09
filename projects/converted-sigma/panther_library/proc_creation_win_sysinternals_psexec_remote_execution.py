# Title: Potential PsExec Remote Execution
# ID: ea011323-7045-460b-b2d7-0f7442ea6b38
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-02-28
# Tags: attack.resource-development, attack.t1587.001
# Description: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential PsExec Remote Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="*accepteula*" AND CommandLine="* -u *" AND CommandLine="* -p *" AND CommandLine="* \\\\\\\\*")) AND NOT (((CommandLine="*\\\\\\\\localhost*" OR CommandLine="*\\\\\\\\127.*"))))
    return True

def title(event):
    return "Potential PsExec Remote Execution"

