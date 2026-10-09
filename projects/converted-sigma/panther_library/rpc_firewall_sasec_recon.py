# Title: Recon Activity via SASec
# ID: 0a3ff354-93fc-4273-8a03-1078782de5b7
# Status: test
# Level: high
# Author: Sagie Dulce, Dekel Paz
# Date: 2022-01-01
# Tags: attack.discovery
# Description: Detects remote RPC calls to read information about scheduled tasks via SASec
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Recon Activity via SASec
def rule(event):
    # Detection Logic:
    # ((EventLog="RPCFW" AND EventID="3" AND InterfaceUuid="378e52b0-c0a9-11cf-822d-00aa0051e40f") AND NOT (((OpNum="0" OR OpNum="1"))))
    return True

def title(event):
    return "Recon Activity via SASec"

