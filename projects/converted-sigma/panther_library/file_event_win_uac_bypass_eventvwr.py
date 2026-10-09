# Title: UAC Bypass Using EventVwr
# ID: 63e4f530-65dc-49cc-8f80-ccfa95c69d43
# Status: test
# Level: high
# Author: Antonio Cocomazzi (idea), Florian Roth (Nextron Systems)
# Date: 2022-04-27
# Tags: attack.privilege-escalation, attack.stealth
# Description: Detects the pattern of a UAC bypass using Windows Event Viewer
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using EventVwr
def rule(event):
    # Detection Logic:
    # (((TargetFilename="*\\Microsoft\\Event Viewer\\RecentViews" OR TargetFilename="*\\Microsoft\\EventV~1\\RecentViews")) AND NOT (((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*"))))
    return True

def title(event):
    return "UAC Bypass Using EventVwr"

