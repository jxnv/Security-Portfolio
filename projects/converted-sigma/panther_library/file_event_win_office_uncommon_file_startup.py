# Title: Uncommon File Created In Office Startup Folder
# ID: a10a2c40-2c4d-49f8-b557-1a946bc55d9d
# Status: test
# Level: high
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-05
# Tags: attack.resource-development, attack.t1587.001
# Description: Detects the creation of a file with an uncommon extension in an Office application startup folder
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon File Created In Office Startup Folder
def rule(event):
    # Detection Logic:
    # (((((TargetFilename="*\\Microsoft\\Word\\STARTUP*") OR ((TargetFilename="*\\Office*" AND TargetFilename="*\\Program Files*" AND TargetFilename="*\\STARTUP*"))) AND NOT (((TargetFilename="*.docb" OR TargetFilename="*.docm" OR TargetFilename="*.docx" OR TargetFilename="*.dotm" OR TargetFilename="*.mdb" OR TargetFilename="*.mdw" OR TargetFilename="*.pdf" OR TargetFilename="*.wll" OR TargetFilename="*.wwl")))) OR (((TargetFilename="*\\Microsoft\\Excel\\XLSTART*") OR ((TargetFilename="*\\Office*" AND TargetFilename="*\\Program Files*" AND TargetFilename="*\\XLSTART*"))) AND NOT (((TargetFilename="*.xll" OR TargetFilename="*.xls" OR TargetFilename="*.xlsm" OR TargetFilename="*.xlsx" OR TargetFilename="*.xlt" OR TargetFilename="*.xltm" OR TargetFilename="*.xlw"))))) AND NOT ((((Image="*:\\Program Files\\Microsoft Office\\*" OR Image="*:\\Program Files (x86)\\Microsoft Office\\*") AND (Image="*\\winword.exe" OR Image="*\\excel.exe")) OR (Image="*:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\*" AND Image="*\\OfficeClickToRun.exe"))))
    return True

def title(event):
    return "Uncommon File Created In Office Startup Folder"

