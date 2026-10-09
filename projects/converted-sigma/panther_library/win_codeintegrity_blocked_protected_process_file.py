# Title: CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked
# ID: 5daf11c3-022b-4969-adb9-365e6c078c7c
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-06
# Tags: attack.privilege-escalation
# Description: Detects block events for files that are disallowed by code integrity for protected processes
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked
def rule(event):
    # Detection Logic:
    # (EventID="3104")
    return True

def title(event):
    return "CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked"

