# Title: Users Added to Global or Device Admin Roles
# ID: 11c767ae-500b-423b-bae3-b234450736ed
# Status: test
# Level: high
# Author: Michael Epping, '@mepples21'
# Date: 2022-06-28
# Tags: attack.persistence, attack.initial-access, attack.privilege-escalation, attack.stealth, attack.t1078.004
# Description: Monitor and alert for users added to device admin roles.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Users Added to Global or Device Admin Roles
def rule(event):
    # Detection Logic:
    # (Category="RoleManagement" AND (OperationName="*Add*" AND OperationName="*member to role*") AND (TargetResources="*7698a772-787b-4ac8-901f-60d6b08affd2*" OR TargetResources="*62e90394-69f5-4237-9190-012177145e10*"))
    return True

def title(event):
    return "Users Added to Global or Device Admin Roles"

