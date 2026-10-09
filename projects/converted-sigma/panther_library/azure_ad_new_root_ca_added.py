# Title: New Root Certificate Authority Added
# ID: 4bb80281-3756-4ec8-a88e-523c5a6fda9e
# Status: test
# Level: medium
# Author: Harjot Shah Singh, '@cyb3rjy0t'
# Date: 2024-03-26
# Tags: attack.credential-access, attack.persistence, attack.privilege-escalation, attack.defense-impairment, attack.t1556
# Description: Detects newly added root certificate authority to an AzureAD tenant to support certificate based authentication.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Root Certificate Authority Added
def rule(event):
    # Detection Logic:
    # (OperationName="Set Company Information" AND TargetResources.modifiedProperties.newValue="*TrustedCAsForPasswordlessAuth*")
    return True

def title(event):
    return "New Root Certificate Authority Added"

