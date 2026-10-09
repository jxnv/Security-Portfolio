# Title: Arbitrary File Download Via MSOHTMED.EXE
# ID: 459f2f98-397b-4a4a-9f47-6a5ec2f1c69d
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-19
# Tags: attack.execution, attack.stealth, attack.t1218
# Description: Detects usage of "MSOHTMED" to download arbitrary files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Arbitrary File Download Via MSOHTMED.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*ftp://*" OR CommandLine="*http://*" OR CommandLine="*https://*")) AND ((Image="*\\MSOHTMED.exe") OR (OriginalFileName="MsoHtmEd.exe")))
    return True

def title(event):
    return "Arbitrary File Download Via MSOHTMED.EXE"

