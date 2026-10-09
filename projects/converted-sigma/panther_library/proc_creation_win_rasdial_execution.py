# Title: Suspicious RASdial Activity
# ID: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
# Status: test
# Level: medium
# Author: juju4
# Date: 2019-01-16
# Tags: attack.execution, attack.t1059
# Description: Detects suspicious process related to rasdial.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious RASdial Activity
def rule(event):
    # Detection Logic:
    # (Image="*rasdial.exe")
    return True

def title(event):
    return "Suspicious RASdial Activity"

