# Title: CodeIntegrity - Revoked Kernel Driver Loaded
# ID: 320fccbf-5e32-4101-82b8-2679c5f007c6
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-06
# Tags: attack.privilege-escalation
# Description: Detects the load of a revoked kernel driver
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CodeIntegrity - Revoked Kernel Driver Loaded
def rule(event):
    # Detection Logic:
    # ((EventID="3021" OR EventID="3022"))
    return True

def title(event):
    return "CodeIntegrity - Revoked Kernel Driver Loaded"

