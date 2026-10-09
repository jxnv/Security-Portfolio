# Title: Potential SolidPDFCreator.DLL Sideloading
# ID: a2edbce1-95c8-4291-8676-0d45146862b3
# Status: test
# Level: medium
# Author: X__Junior (Nextron Systems)
# Date: 2023-05-07
# Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
# Description: Detects potential DLL sideloading of "SolidPDFCreator.dll"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential SolidPDFCreator.DLL Sideloading
def rule(event):
    # Detection Logic:
    # ((ImageLoaded="*\\SolidPDFCreator.dll") AND NOT ((Image="*\\SolidPDFCreator.exe" AND (ImageLoaded="C:\\Program Files (x86)\\SolidDocuments\\SolidPDFCreator\\*" OR ImageLoaded="C:\\Program Files\\SolidDocuments\\SolidPDFCreator\\*"))))
    return True

def title(event):
    return "Potential SolidPDFCreator.DLL Sideloading"

