# Title: SyncAppvPublishingServer Bypass Powershell Restriction - PS Module
# ID: fe5ce7eb-dad8-467c-84a9-31ec23bd644a
# Status: test
# Level: medium
# Author: Ensar Şamil, @sblmsrsn, OSCD Community
# Date: 2020-10-05
# Tags: attack.stealth, attack.t1218
# Description: Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SyncAppvPublishingServer Bypass Powershell Restriction - PS Module
def rule(event):
    # Detection Logic:
    # (ContextInfo="*SyncAppvPublishingServer.exe*")
    return True

def title(event):
    return "SyncAppvPublishingServer Bypass Powershell Restriction - PS Module"

