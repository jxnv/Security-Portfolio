# Title: SharpHound Recon Account Discovery
# ID: 65f77b1e-8e79-45bf-bb67-5988a8ce45a5
# Status: test
# Level: high
# Author: Sagie Dulce, Dekel Paz
# Date: 2022-01-01
# Tags: attack.t1087, attack.discovery
# Description: Detects remote RPC calls useb by SharpHound to map remote connections and local group membership.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SharpHound Recon Account Discovery
def rule(event):
    # Detection Logic:
    # (EventLog="RPCFW" AND EventID="3" AND InterfaceUuid="6bffd098-a112-3610-9833-46c3f87e345a" AND OpNum="2")
    return True

def title(event):
    return "SharpHound Recon Account Discovery"

