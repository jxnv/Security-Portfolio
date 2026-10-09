# Title: Remote Access Tool - ScreenConnect Installation Execution
# ID: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2021-02-11
# Tags: attack.persistence, attack.initial-access, attack.t1133
# Description: Detects ScreenConnect program starts that establish a remote access to a system.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Access Tool - ScreenConnect Installation Execution
def rule(event):
    # Detection Logic:
    # ((CommandLine="*e=Access&*" AND CommandLine="*y=Guest&*" AND CommandLine="*&p=*" AND CommandLine="*&c=*" AND CommandLine="*&k=*"))
    return True

def title(event):
    return "Remote Access Tool - ScreenConnect Installation Execution"

