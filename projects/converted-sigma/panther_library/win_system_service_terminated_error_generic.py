# Title: Windows Service Terminated With Error
# ID: acfa2210-0d71-4eeb-b477-afab494d596c
# Status: test
# Level: low
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-04-14
# Tags: attack.stealth
# Description: Detects Windows services that got terminated for whatever reason
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Service Terminated With Error
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND EventID="7023")
    return True

def title(event):
    return "Windows Service Terminated With Error"

