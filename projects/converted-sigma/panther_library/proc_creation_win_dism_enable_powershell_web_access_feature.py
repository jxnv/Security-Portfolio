# Title: PowerShell Web Access Feature Enabled Via DISM
# ID: 7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f
# Status: test
# Level: high
# Author: Michael Haag
# Date: 2024-09-03
# Tags: attack.privilege-escalation, attack.persistence, attack.t1548.002
# Description: Detects the use of DISM to enable the PowerShell Web Access feature, which could be used for remote access and potential abuse
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Web Access Feature Enabled Via DISM
def rule(event):
    # Detection Logic:
    # (((CommandLine="*WindowsPowerShellWebAccess*" AND CommandLine="*/online*" AND CommandLine="*/enable-feature*")) AND ((Image="*\\dism.exe") OR (OriginalFileName="DISM.EXE")))
    return True

def title(event):
    return "PowerShell Web Access Feature Enabled Via DISM"

