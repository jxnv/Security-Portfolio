# Title: Malicious IP Address Sign-In Suspicious
# ID: 36440e1c-5c22-467a-889b-593e66498472
# Status: test
# Level: high
# Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
# Date: 2023-09-07
# Tags: attack.t1090, attack.command-and-control
# Description: Indicates sign-in from a malicious IP address known to be malicious at time of sign-in.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Malicious IP Address Sign-In Suspicious
def rule(event):
    # Detection Logic:
    # (riskEventType="suspiciousIPAddress")
    return True

def title(event):
    return "Malicious IP Address Sign-In Suspicious"

