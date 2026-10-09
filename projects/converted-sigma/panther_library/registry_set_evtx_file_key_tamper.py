# Title: Potential EventLog File Location Tampering
# ID: 0cb8d736-995d-4ce7-a31e-1e8d452a1459
# Status: test
# Level: high
# Author: D3F7A5105
# Date: 2023-01-02
# Tags: attack.defense-impairment, attack.t1685.001
# Description: Detects tampering with EventLog service "file" key. In order to change the default location of an Evtx file. This technique is used to tamper with log collection and alerting
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential EventLog File Location Tampering
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\*" AND TargetObject="*\\File") AND NOT ((Details="*\\System32\\Winevt\\Logs\\*")))
    return True

def title(event):
    return "Potential EventLog File Location Tampering"

