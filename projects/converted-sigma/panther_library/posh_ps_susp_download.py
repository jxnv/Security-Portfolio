# Title: Suspicious PowerShell Download - Powershell Script
# ID: 403c2cc0-7f6b-4925-9423-bfa573bed7eb
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2017-03-05
# Tags: attack.execution, attack.t1059.001
# Description: Detects suspicious PowerShell download command
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Download - Powershell Script
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*System.Net.WebClient*") AND ((ScriptBlockText="*.DownloadFile(*" OR ScriptBlockText="*.DownloadFileAsync(*" OR ScriptBlockText="*.DownloadString(*" OR ScriptBlockText="*.DownloadStringAsync(*")))
    return True

def title(event):
    return "Suspicious PowerShell Download - Powershell Script"

