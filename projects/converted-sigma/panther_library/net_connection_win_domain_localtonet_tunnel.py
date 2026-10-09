# Title: Communication To LocaltoNet Tunneling Service Initiated
# ID: 3ab65069-d82a-4d44-a759-466661a082d1
# Status: test
# Level: high
# Author: Andreas Braathen (mnemonic.io)
# Date: 2024-06-17
# Tags: attack.command-and-control, attack.t1572, attack.t1090, attack.t1102
# Description: Detects an executable initiating a network connection to "LocaltoNet" tunneling sub-domains.
# LocaltoNet is a reverse proxy that enables localhost services to be exposed to the Internet.
# Attackers have been seen to use this service for command-and-control activities to bypass MFA and perimeter controls.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Communication To LocaltoNet Tunneling Service Initiated
def rule(event):
    # Detection Logic:
    # ((DestinationHostname="*.localto.net" OR DestinationHostname="*.localtonet.com") AND Initiated="true")
    return True

def title(event):
    return "Communication To LocaltoNet Tunneling Service Initiated"

