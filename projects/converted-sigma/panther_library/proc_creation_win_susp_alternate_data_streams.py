# Title: Execute From Alternate Data Streams
# ID: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-09-01
# Tags: attack.stealth, attack.t1564.004
# Description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Execute From Alternate Data Streams
def rule(event):
    # Detection Logic:
    # ((CommandLine="*txt:*") AND (((CommandLine="*esentutl *" AND CommandLine="* /y *" AND CommandLine="* /d *" AND CommandLine="* /o *")) OR ((CommandLine="*makecab *" AND CommandLine="*.cab*")) OR ((CommandLine="*reg *" AND CommandLine="* export *")) OR ((CommandLine="*regedit *" AND CommandLine="* /E *")) OR ((CommandLine="*type *" AND CommandLine="* > *"))))
    return True

def title(event):
    return "Execute From Alternate Data Streams"

