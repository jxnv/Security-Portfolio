# Title: SharpHound Recon Sessions
# ID: 6d580420-ff3f-4e0e-b6b0-41b90c787e28
# Status: test
# Level: high
# Author: Sagie Dulce, Dekel Paz
# Date: 2022-01-01
# Tags: attack.discovery, attack.t1033
# Description: Detects remote RPC calls useb by SharpHound to map remote connections and local group membership.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SharpHound Recon Sessions
def rule(event):
    # Detection Logic:
    # (EventLog="RPCFW" AND EventID="3" AND InterfaceUuid="4b324fc8-1670-01d3-1278-5a47bf6ee188" AND OpNum="12")
    return True

def title(event):
    return "SharpHound Recon Sessions"

