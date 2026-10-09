# Title: Taskmgr as LOCAL_SYSTEM
# ID: 9fff585c-c33e-4a86-b3cd-39312079a65f
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2018-03-18
# Tags: attack.stealth, attack.t1036
# Description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Taskmgr as LOCAL_SYSTEM
def rule(event):
    # Detection Logic:
    # ((User="*AUTHORI*" OR User="*AUTORI*") AND Image="*\\taskmgr.exe")
    return True

def title(event):
    return "Taskmgr as LOCAL_SYSTEM"

