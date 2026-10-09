# Title: Windows AppX Deployment Unsigned Package Installation
# ID: 9a025188-6f2d-42f8-bb2f-d3a83d24a5af
# Status: experimental
# Level: medium
# Author: Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-11-03
# Tags: attack.execution, attack.defense-impairment, attack.t1204.002, attack.t1553.005
# Description: Detects attempts to install unsigned MSIX/AppX packages using the -AllowUnsigned parameter via AppXDeployment-Server events
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows AppX Deployment Unsigned Package Installation
def rule(event):
    # Detection Logic:
    # (EventID="603" AND Flags="8388608")
    return True

def title(event):
    return "Windows AppX Deployment Unsigned Package Installation"

