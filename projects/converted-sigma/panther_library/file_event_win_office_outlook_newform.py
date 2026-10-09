# Title: Potential Persistence Via Outlook Form
# ID: c3edc6a5-d9d4-48d8-930e-aab518390917
# Status: test
# Level: high
# Author: Tobias Michalski (Nextron Systems)
# Date: 2021-06-10
# Tags: attack.persistence, attack.t1137.003
# Description: Detects the creation of a new Outlook form which can contain malicious code
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via Outlook Form
def rule(event):
    # Detection Logic:
    # (Image="*\\outlook.exe" AND (TargetFilename="*\\AppData\\Local\\Microsoft\\FORMS\\IPM*" OR TargetFilename="*\\Local Settings\\Application Data\\Microsoft\\Forms*"))
    return True

def title(event):
    return "Potential Persistence Via Outlook Form"

