# Title: CodeIntegrity - Unsigned Image Loaded
# ID: c92c24e7-f595-493f-9c98-53d5142f5c18
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-06
# Tags: attack.privilege-escalation
# Description: Detects loaded unsigned image on the system
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CodeIntegrity - Unsigned Image Loaded
def rule(event):
    # Detection Logic:
    # (EventID="3037")
    return True

def title(event):
    return "CodeIntegrity - Unsigned Image Loaded"

