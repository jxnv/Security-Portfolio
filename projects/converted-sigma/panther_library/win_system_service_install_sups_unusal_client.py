# Title: Service Installed By Unusual Client - System
# ID: 71c276aa-49cd-43d2-b920-2dcd3e6962d5
# Status: test
# Level: high
# Author: Tim Rauch (Nextron Systems), Elastic (idea)
# Date: 2022-09-15
# Tags: attack.persistence, attack.privilege-escalation, attack.t1543
# Description: Detects a service installed by a client which has PID 0 or whose parent has PID 0
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service Installed By Unusual Client - System
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND EventID="7045" AND ProcessId="0")
    return True

def title(event):
    return "Service Installed By Unusual Client - System"

