# Title: Potential Recon Activity Using DriverQuery.EXE
# ID: 9fc3072c-dc8f-4bf7-b231-18950000fadd
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-19
# Tags: attack.discovery
# Description: Detect usage of the "driverquery" utility to perform reconnaissance on installed drivers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Recon Activity Using DriverQuery.EXE
def rule(event):
    # Detection Logic:
    # (((Image="*driverquery.exe") OR (OriginalFileName="drvqry.exe")) AND (((ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\wscript.exe")) OR ((ParentImage="*\\AppData\\Local\\*" OR ParentImage="*\\Users\\Public\\*" OR ParentImage="*\\Windows\\Temp\\*"))))
    return True

def title(event):
    return "Potential Recon Activity Using DriverQuery.EXE"

