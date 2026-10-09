# Title: Atypical Travel
# ID: 1a41023f-1e70-4026-921a-4d9341a9038e
# Status: test
# Level: high
# Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
# Date: 2023-09-03
# Tags: attack.stealth, attack.t1078, attack.persistence, attack.privilege-escalation, attack.initial-access
# Description: Identifies two sign-ins originating from geographically distant locations, where at least one of the locations may also be atypical for the user, given past behavior.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Atypical Travel
def rule(event):
    # Detection Logic:
    # (riskEventType="unlikelyTravel")
    return True

def title(event):
    return "Atypical Travel"

