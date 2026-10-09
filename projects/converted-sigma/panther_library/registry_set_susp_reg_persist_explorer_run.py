# Title: Registry Persistence via Explorer Run Key
# ID: b7916c2a-fa2f-4795-9477-32b731f70f11
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), oscd.community
# Date: 2018-07-18
# Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
# Description: Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Registry Persistence via Explorer Run Key
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" AND (Details="*:\\$Recycle.bin\\*" OR Details="*:\\ProgramData\\*" OR Details="*:\\Temp\\*" OR Details="*:\\Users\\Default\\*" OR Details="*:\\Users\\Public\\*" OR Details="*:\\Windows\\Temp\\*" OR Details="*\\AppData\\Local\\Temp\\*"))
    return True

def title(event):
    return "Registry Persistence via Explorer Run Key"

