# Title: Suspicious Remote Child Process From Outlook
# ID: e212d415-0e93-435f-9e1a-f29005bb4723
# Status: test
# Level: high
# Author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
# Date: 2018-12-27
# Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
# Description: Detects a suspicious child process spawning from Outlook where the image is located in a remote location (SMB/WebDav shares).
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Remote Child Process From Outlook
def rule(event):
    # Detection Logic:
    # (ParentImage="*\\outlook.exe" AND Image="\\\\\\\\*")
    return True

def title(event):
    return "Suspicious Remote Child Process From Outlook"

