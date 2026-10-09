# Title: Potential Discovery Activity Via Dnscmd.EXE
# ID: b6457d63-d2a2-4e29-859d-4e7affc153d1
# Status: test
# Level: medium
# Author: @gott_cyber
# Date: 2022-07-31
# Tags: attack.discovery, attack.execution
# Description: Detects an attempt to leverage dnscmd.exe to enumerate the DNS zones of a domain. DNS zones used to host the DNS records for a particular domain.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Discovery Activity Via Dnscmd.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/enumrecords*" OR CommandLine="*/enumzones*" OR CommandLine="*/ZonePrint*" OR CommandLine="*/info*")) AND (Image="*\\dnscmd.exe"))
    return True

def title(event):
    return "Potential Discovery Activity Via Dnscmd.EXE"

