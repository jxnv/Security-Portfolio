# Title: Potential Persistence Via Mpnotify
# ID: 92772523-d9c1-4c93-9547-b0ca500baba3
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-21
# Tags: attack.persistence
# Description: Detects when an attacker register a new SIP provider for persistence and defense evasion
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via Mpnotify
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\mpnotify*")
    return True

def title(event):
    return "Potential Persistence Via Mpnotify"

