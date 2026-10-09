# Title: Netcat The Powershell Version
# ID: c5b20776-639a-49bf-94c7-84f912b91c15
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-07-21
# Tags: attack.command-and-control, attack.execution, attack.t1095, attack.t1059.001
# Description: Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Netcat The Powershell Version
def rule(event):
    # Detection Logic:
    # ((Data="*powercat *" OR Data="*powercat.ps1*"))
    return True

def title(event):
    return "Netcat The Powershell Version"

