# Title: Potential Attachment Manager Settings Associations Tamper
# ID: a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-01
# Tags: attack.defense-impairment
# Description: Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Attachment Manager Settings Associations Tamper
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\*") AND ((TargetObject="*\\DefaultFileTypeRisk" AND Details="DWORD (0x00006152)") OR (TargetObject="*\\LowRiskFileTypes" AND (Details="*.zip;*" OR Details="*.rar;*" OR Details="*.exe;*" OR Details="*.bat;*" OR Details="*.com;*" OR Details="*.cmd;*" OR Details="*.reg;*" OR Details="*.msi;*" OR Details="*.htm;*" OR Details="*.html;*"))))
    return True

def title(event):
    return "Potential Attachment Manager Settings Associations Tamper"

