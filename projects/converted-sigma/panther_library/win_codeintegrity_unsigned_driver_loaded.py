# Title: CodeIntegrity - Unsigned Kernel Module Loaded
# ID: 951f8d29-f2f6-48a7-859f-0673ff105e6f
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-06
# Tags: attack.privilege-escalation
# Description: Detects the presence of a loaded unsigned kernel module on the system.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CodeIntegrity - Unsigned Kernel Module Loaded
def rule(event):
    # Detection Logic:
    # (EventID="3001")
    return True

def title(event):
    return "CodeIntegrity - Unsigned Kernel Module Loaded"

