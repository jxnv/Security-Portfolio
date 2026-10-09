# Title: UAC Bypass Using Event Viewer RecentViews
# ID: 30fc8de7-d833-40c4-96b6-28319fbc4f6c
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-11-22
# Tags: attack.privilege-escalation, attack.stealth
# Description: Detects the pattern of UAC Bypass using Event Viewer RecentViews
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using Event Viewer RecentViews
def rule(event):
    # Detection Logic:
    # (((CommandLine="*\\Event Viewer\\RecentViews*" OR CommandLine="*\\EventV~1\\RecentViews*")) AND (CommandLine="*>*"))
    return True

def title(event):
    return "UAC Bypass Using Event Viewer RecentViews"

