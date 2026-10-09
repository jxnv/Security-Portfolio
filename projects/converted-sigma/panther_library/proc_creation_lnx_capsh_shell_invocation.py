# Title: Capsh Shell Invocation - Linux
# ID: db1ac3be-f606-4e3a-89e0-9607cbe6b98a
# Status: test
# Level: high
# Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
# Date: 2024-09-02
# Tags: attack.execution, attack.t1059
# Description: Detects the use of the "capsh" utility to invoke a shell.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Capsh Shell Invocation - Linux
def rule(event):
    # Detection Logic:
    # (Image="*/capsh" AND CommandLine="* --")
    return True

def title(event):
    return "Capsh Shell Invocation - Linux"

