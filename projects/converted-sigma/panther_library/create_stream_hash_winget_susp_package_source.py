# Title: Potential Suspicious Winget Package Installation
# ID: a3f5c081-e75b-43a0-9f5b-51f26fe5dba2
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-04-18
# Tags: attack.persistence, attack.stealth
# Description: Detects potential suspicious winget package installation from a suspicious source.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Suspicious Winget Package Installation
def rule(event):
    # Detection Logic:
    # (Contents="[ZoneTransfer]  ZoneId=3*" AND (Contents="*://1*" OR Contents="*://2*" OR Contents="*://3*" OR Contents="*://4*" OR Contents="*://5*" OR Contents="*://6*" OR Contents="*://7*" OR Contents="*://8*" OR Contents="*://9*") AND TargetFilename="*:Zone.Identifier" AND TargetFilename="*\\AppData\\Local\\Temp\\WinGet\\*")
    return True

def title(event):
    return "Potential Suspicious Winget Package Installation"

