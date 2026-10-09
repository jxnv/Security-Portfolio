# Title: Suspicious RDP Redirect Using TSCON
# ID: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2018-03-17
# Tags: attack.lateral-movement, attack.t1563.002, attack.t1021.001, car.2013-07-002
# Description: Detects a suspicious RDP session redirect using tscon.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious RDP Redirect Using TSCON
def rule(event):
    # Detection Logic:
    # (CommandLine="* /dest:rdp-tcp#*")
    return True

def title(event):
    return "Suspicious RDP Redirect Using TSCON"

