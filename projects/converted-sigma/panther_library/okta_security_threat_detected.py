# Title: Okta Security Threat Detected
# ID: 5c82f0b9-3c6d-477f-a318-0e14a1df73e0
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.command-and-control
# Description: Detects when an security threat is detected in Okta.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Security Threat Detected
def rule(event):
    # Detection Logic:
    # (eventType="security.threat.detected")
    return True

def title(event):
    return "Okta Security Threat Detected"

