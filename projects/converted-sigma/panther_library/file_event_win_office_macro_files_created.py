# Title: Office Macro File Creation
# ID: 91174a41-dc8f-401b-be89-7bfc140612a0
# Status: test
# Level: low
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-01-23
# Tags: attack.initial-access, attack.t1566.001
# Description: Detects the creation of a new office macro files on the systems
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Office Macro File Creation
def rule(event):
    # Detection Logic:
    # (((TargetFilename="*.docm" OR TargetFilename="*.dotm" OR TargetFilename="*.xlsm" OR TargetFilename="*.xltm" OR TargetFilename="*.potm" OR TargetFilename="*.pptm")) AND NOT (((Image="C:\\Program Files\\Microsoft Office\\*" OR Image="C:\\Program Files (x86)\\Microsoft Office\\*") AND (Image="*\\WINWORD.EXE" OR Image="*\\EXCEL.EXE" OR Image="*\\POWERPNT.EXE") AND TargetFilename="*\\~$*")))
    return True

def title(event):
    return "Office Macro File Creation"

