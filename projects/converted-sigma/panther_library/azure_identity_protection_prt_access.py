# Title: Primary Refresh Token Access Attempt
# ID: a84fc3b1-c9ce-4125-8e74-bdcdb24021f1
# Status: test
# Level: high
# Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
# Date: 2023-09-07
# Tags: attack.t1528, attack.credential-access
# Description: Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Primary Refresh Token Access Attempt
def rule(event):
    # Detection Logic:
    # (riskEventType="attemptedPrtAccess")
    return True

def title(event):
    return "Primary Refresh Token Access Attempt"

