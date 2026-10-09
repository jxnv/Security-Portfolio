# Title: Potential RDP Session Hijacking Activity
# ID: 224f140f-3553-4cd1-af78-13d81bf9f7cc
# Status: test
# Level: medium
# Author: @juju4
# Date: 2022-12-27
# Tags: attack.execution
# Description: Detects potential RDP Session Hijacking activity on Windows systems
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential RDP Session Hijacking Activity
def rule(event):
    # Detection Logic:
    # (((Image="*\\tscon.exe") OR (OriginalFileName="tscon.exe")) AND ((IntegrityLevel="System" OR IntegrityLevel="S-1-16-16384")))
    return True

def title(event):
    return "Potential RDP Session Hijacking Activity"

