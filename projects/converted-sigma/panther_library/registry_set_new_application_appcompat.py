# Title: New Application in AppCompat
# ID: 60936b49-fca0-4f32-993d-7415edcf9a5d
# Status: test
# Level: informational
# Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
# Date: 2020-05-02
# Tags: attack.execution, attack.t1204.002
# Description: A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Application in AppCompat
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\AppCompatFlags\\Compatibility Assistant\\Store\\*")
    return True

def title(event):
    return "New Application in AppCompat"

