# Title: File Download From IP Based URL Via CertOC.EXE
# ID: b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-10-18
# Tags: attack.command-and-control, attack.execution, attack.t1105
# Description: Detects when a user downloads a file from an IP based URL using CertOC.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: File Download From IP Based URL Via CertOC.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="*-GetCACAPS*") AND ((Image="*\\certoc.exe") OR (OriginalFileName="CertOC.exe")) AND (CommandLine=regex("://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")))
    return True

def title(event):
    return "File Download From IP Based URL Via CertOC.EXE"

