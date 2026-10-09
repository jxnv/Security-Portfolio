# Title: Outlook Security Settings Updated - Registry
# ID: c3cefdf4-6703-4e1c-bad8-bf422fc5015a
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-12-28
# Tags: attack.persistence, attack.t1137
# Description: Detects changes to the registry values related to outlook security settings
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Outlook Security Settings Updated - Registry
def rule(event):
    # Detection Logic:
    # (((TargetObject="*\\SOFTWARE\\Microsoft\\Office\\*" AND TargetObject="*\\Outlook\\Security\\*")) AND NOT (((Image="C:\\Program Files\\Microsoft Office\\*" OR Image="C:\\Program Files (x86)\\Microsoft Office\\*") AND Image="*\\OUTLOOK.EXE")))
    return True

def title(event):
    return "Outlook Security Settings Updated - Registry"

