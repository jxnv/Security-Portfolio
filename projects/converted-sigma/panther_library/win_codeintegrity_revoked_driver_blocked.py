# Title: CodeIntegrity - Blocked Driver Load With Revoked Certificate
# ID: 9b72b82d-f1c5-4632-b589-187159bc6ec1
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-06
# Tags: attack.persistence, attack.privilege-escalation, attack.t1543
# Description: Detects blocked load attempts of revoked drivers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CodeIntegrity - Blocked Driver Load With Revoked Certificate
def rule(event):
    # Detection Logic:
    # (EventID="3023")
    return True

def title(event):
    return "CodeIntegrity - Blocked Driver Load With Revoked Certificate"

