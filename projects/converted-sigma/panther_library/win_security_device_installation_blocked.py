# Title: Device Installation Blocked
# ID: c9eb55c3-b468-40ab-9089-db2862e42137
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-10-14
# Tags: attack.initial-access, attack.t1200
# Description: Detects an installation of a device that is forbidden by the system policy
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Device Installation Blocked
def rule(event):
    # Detection Logic:
    # (EventID="6423")
    return True

def title(event):
    return "Device Installation Blocked"

