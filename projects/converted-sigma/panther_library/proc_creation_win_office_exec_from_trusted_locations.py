# Title: Potentially Suspicious Office Document Executed From Trusted Location
# ID: f99abdf0-6283-4e71-bd2b-b5c048a94743
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-21
# Tags: attack.stealth, attack.t1202
# Description: Detects the execution of an Office application that points to a document that is located in a trusted location. Attackers often used this to avoid macro security and execute their malicious code.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious Office Document Executed From Trusted Location
def rule(event):
    # Detection Logic:
    # (((((Image="*\\EXCEL.EXE" OR Image="*\\POWERPNT.EXE" OR Image="*\\WINWORD.exe")) OR ((OriginalFileName="Excel.exe" OR OriginalFileName="POWERPNT.EXE" OR OriginalFileName="WinWord.exe"))) AND ((ParentImage="*\\explorer.exe" OR ParentImage="*\\dopus.exe")) AND ((CommandLine="*\\AppData\\Roaming\\Microsoft\\Templates*" OR CommandLine="*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*" OR CommandLine="*\\Microsoft Office\\root\\Templates\\*" OR CommandLine="*\\Microsoft Office\\Templates\\*"))) AND NOT (((CommandLine="*.dotx" OR CommandLine="*.xltx" OR CommandLine="*.potx"))))
    return True

def title(event):
    return "Potentially Suspicious Office Document Executed From Trusted Location"

