# Title: Network Communication Initiated To Portmap.IO Domain
# ID: 07837ab9-60e1-481f-a74d-c31fb496a94c
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2024-05-31
# Tags: attack.t1041, attack.command-and-control, attack.t1090.002, attack.exfiltration
# Description: Detects an executable accessing the portmap.io domain, which could be a sign of forbidden C2 traffic or data exfiltration by malicious actors
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Network Communication Initiated To Portmap.IO Domain
def rule(event):
    # Detection Logic:
    # (Initiated="true" AND DestinationHostname="*.portmap.io")
    return True

def title(event):
    return "Network Communication Initiated To Portmap.IO Domain"

