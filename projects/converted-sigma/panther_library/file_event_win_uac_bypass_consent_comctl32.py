# Title: UAC Bypass Using Consent and Comctl32 - File
# ID: 62ed5b55-f991-406a-85d9-e8e8fdf18789
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-23
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass Using Consent and Comctl32 - File
def rule(event):
    # Detection Logic:
    # (TargetFilename="C:\\Windows\\System32\\consent.exe.@*" AND TargetFilename="*\\comctl32.dll")
    return True

def title(event):
    return "UAC Bypass Using Consent and Comctl32 - File"

