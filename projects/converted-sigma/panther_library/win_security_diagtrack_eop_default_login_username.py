# Title: DiagTrackEoP Default Login Username
# ID: 2111118f-7e46-4fc8-974a-59fd8ec95196
# Status: test
# Level: critical
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-03
# Tags: attack.privilege-escalation
# Description: Detects the default "UserName" used by the DiagTrackEoP POC
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DiagTrackEoP Default Login Username
def rule(event):
    # Detection Logic:
    # (EventID="4624" AND LogonType="9" AND TargetOutboundUserName="thisisnotvaliduser")
    return True

def title(event):
    return "DiagTrackEoP Default Login Username"

