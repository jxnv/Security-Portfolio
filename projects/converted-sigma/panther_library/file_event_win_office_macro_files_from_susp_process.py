# Title: Office Macro File Creation From Suspicious Process
# ID: b1c50487-1967-4315-a026-6491686d860e
# Status: test
# Level: high
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-01-23
# Tags: attack.initial-access, attack.t1566.001
# Description: Detects the creation of a office macro file from a a suspicious process
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Office Macro File Creation From Suspicious Process
def rule(event):
    # Detection Logic:
    # ((((Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\wscript.exe"))) AND ((TargetFilename="*.docm" OR TargetFilename="*.dotm" OR TargetFilename="*.xlsm" OR TargetFilename="*.xltm" OR TargetFilename="*.potm" OR TargetFilename="*.pptm")))
    return True

def title(event):
    return "Office Macro File Creation From Suspicious Process"

