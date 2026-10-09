# Title: ESXi Account Creation Via ESXCLI
# ID: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
# Status: test
# Level: medium
# Author: Cedric Maurugeon
# Date: 2023-08-22
# Tags: attack.persistence, attack.execution, attack.t1136, attack.t1059.012
# Description: Detects user account creation on ESXi system via esxcli
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: ESXi Account Creation Via ESXCLI
def rule(event):
    # Detection Logic:
    # (Image="*/esxcli" AND (CommandLine="*system *" AND CommandLine="*account *" AND CommandLine="*add *"))
    return True

def title(event):
    return "ESXi Account Creation Via ESXCLI"

