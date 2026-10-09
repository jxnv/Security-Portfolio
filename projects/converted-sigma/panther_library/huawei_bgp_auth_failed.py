# Title: Huawei BGP Authentication Failures
# ID: a557ffe6-ac54-43d2-ae69-158027082350
# Status: test
# Level: low
# Author: Tim Brown
# Date: 2023-01-09
# Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.credential-access, attack.collection, attack.stealth, attack.t1078, attack.t1110, attack.t1557
# Description: Detects BGP failures which may be indicative of brute force attacks to manipulate routing.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Huawei BGP Authentication Failures
def rule(event):
    # Detection Logic:
    # ((=":179" AND ="BGP_AUTH_FAILED"))
    return True

def title(event):
    return "Huawei BGP Authentication Failures"

