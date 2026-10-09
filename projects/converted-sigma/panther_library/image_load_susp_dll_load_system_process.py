# Title: DLL Load By System Process From Suspicious Locations
# ID: 9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-17
# Tags: attack.stealth, attack.t1070
# Description: Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DLL Load By System Process From Suspicious Locations
def rule(event):
    # Detection Logic:
    # (Image="C:\\Windows\\*" AND (ImageLoaded="C:\\Users\\Public\\*" OR ImageLoaded="C:\\PerfLogs\\*"))
    return True

def title(event):
    return "DLL Load By System Process From Suspicious Locations"

