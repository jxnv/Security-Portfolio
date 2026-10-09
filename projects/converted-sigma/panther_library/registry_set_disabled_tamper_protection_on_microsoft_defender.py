# Title: Disable Tamper Protection on Windows Defender
# ID: 93d298a1-d28f-47f1-a468-d971e7796679
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-04
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects disabling Windows Defender Tamper Protection
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Disable Tamper Protection on Windows Defender
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\Microsoft\\Windows Defender\\Features\\TamperProtection*" AND Details="DWORD (0x00000000)") AND NOT (((Image="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" AND Image="*\\MsMpEng.exe") OR (Image="C:\\Program Files\\Windows Defender\\MsMpEng.exe"))))
    return True

def title(event):
    return "Disable Tamper Protection on Windows Defender"

