# Title: Driver Added To Disallowed Images In HVCI - Registry
# ID: 555155a2-03bf-4fe7-af74-d176b3fdbe16
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems), Omar Khaled (@beacon_exe)
# Date: 2023-12-05
# Tags: attack.stealth
# Description: Detects changes to the "HVCIDisallowedImages" registry value to potentially add a driver to the list, in order to prevent it from loading.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Driver Added To Disallowed Images In HVCI - Registry
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\Control\\CI\\*" AND TargetObject="*\\HVCIDisallowedImages*"))
    return True

def title(event):
    return "Driver Added To Disallowed Images In HVCI - Registry"

