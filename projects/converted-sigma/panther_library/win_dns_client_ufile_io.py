# Title: DNS Query To Ufile.io - DNS Client
# ID: 090ffaad-c01a-4879-850c-6d57da98452d
# Status: test
# Level: low
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-16
# Tags: attack.exfiltration, attack.t1567.002
# Description: Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DNS Query To Ufile.io - DNS Client
def rule(event):
    # Detection Logic:
    # (EventID="3008" AND QueryName="*ufile.io*")
    return True

def title(event):
    return "DNS Query To Ufile.io - DNS Client"

