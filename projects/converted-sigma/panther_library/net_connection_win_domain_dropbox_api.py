# Title: Suspicious Dropbox API Usage
# ID: 25eabf56-22f0-4915-a1ed-056b8dae0a68
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-04-20
# Tags: attack.command-and-control, attack.exfiltration, attack.t1105, attack.t1567.002
# Description: Detects an executable that isn't dropbox but communicates with the Dropbox API
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Dropbox API Usage
def rule(event):
    # Detection Logic:
    # ((Initiated="true" AND (DestinationHostname="*api.dropboxapi.com" OR DestinationHostname="*content.dropboxapi.com")) AND NOT ((Image="*\\Dropbox*")))
    return True

def title(event):
    return "Suspicious Dropbox API Usage"

