# Title: Arbitrary File Download Via PresentationHost.EXE
# ID: b124ddf4-778d-418e-907f-6dd3fc0d31cd
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-19
# Tags: attack.execution, attack.stealth, attack.t1218
# Description: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Arbitrary File Download Via PresentationHost.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*http://*" OR CommandLine="*https://*" OR CommandLine="*ftp://*")) AND ((Image="*\\presentationhost.exe") OR (OriginalFileName="PresentationHost.exe")))
    return True

def title(event):
    return "Arbitrary File Download Via PresentationHost.EXE"

