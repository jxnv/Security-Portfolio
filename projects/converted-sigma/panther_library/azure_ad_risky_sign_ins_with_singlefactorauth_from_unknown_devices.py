# Title: Suspicious SignIns From A Non Registered Device
# ID: 572b12d4-9062-11ed-a1eb-0242ac120002
# Status: test
# Level: high
# Author: Harjot Singh, '@cyb3rjy0t'
# Date: 2023-01-10
# Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.stealth, attack.t1078
# Description: Detects risky authentication from a non AD registered device without MFA being required.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious SignIns From A Non Registered Device
def rule(event):
    # Detection Logic:
    # ((Status="Success" AND AuthenticationRequirement="singleFactorAuthentication" AND RiskState="atRisk") AND ((DeviceDetail.trusttype="") OR (NOT DeviceDetail.trusttype=*)))
    return True

def title(event):
    return "Suspicious SignIns From A Non Registered Device"

