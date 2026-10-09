# Title: Potential CCleanerDU.DLL Sideloading
# ID: 1fbc0671-5596-4e17-8682-f020a0b995dc
# Status: test
# Level: medium
# Author: X__Junior (Nextron Systems)
# Date: 2023-07-13
# Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
# Description: Detects potential DLL sideloading of "CCleanerDU.dll"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential CCleanerDU.DLL Sideloading
def rule(event):
    # Detection Logic:
    # ((ImageLoaded="*\\CCleanerDU.dll") AND NOT (((Image="C:\\Program Files\\CCleaner\\*" OR Image="C:\\Program Files (x86)\\CCleaner\\*") AND (Image="*\\CCleaner.exe" OR Image="*\\CCleaner64.exe"))))
    return True

def title(event):
    return "Potential CCleanerDU.DLL Sideloading"

