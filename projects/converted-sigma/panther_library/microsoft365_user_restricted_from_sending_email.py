# Title: Microsoft 365 - User Restricted from Sending Email
# ID: ff246f56-7f24-402a-baca-b86540e3925c
# Status: test
# Level: medium
# Author: austinsonger
# Date: 2021-08-19
# Tags: attack.initial-access, attack.t1199
# Description: Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Microsoft 365 - User Restricted from Sending Email
def rule(event):
    # Detection Logic:
    # (eventSource="SecurityComplianceCenter" AND eventName="User restricted from sending email" AND status="success")
    return True

def title(event):
    return "Microsoft 365 - User Restricted from Sending Email"

