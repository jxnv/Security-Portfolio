# Title: Disable Privacy Settings Experience in Registry
# ID: 0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-10-02
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects registry modifications that disable Privacy Settings Experience
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Disable Privacy Settings Experience in Registry
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SOFTWARE\\Policies\\Microsoft\\Windows\\OOBE\\DisablePrivacyExperience" AND Details="DWORD (0x00000000)")
    return True

def title(event):
    return "Disable Privacy Settings Experience in Registry"

