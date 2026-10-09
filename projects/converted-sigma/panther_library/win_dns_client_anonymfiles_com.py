# Title: DNS Query for Anonfiles.com Domain - DNS Client
# ID: 29f171d7-aa47-42c7-9c7b-3c87938164d9
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-16
# Tags: attack.exfiltration, attack.t1567.002
# Description: Detects DNS queries for anonfiles.com, which is an anonymous file upload platform often used for malicious purposes
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DNS Query for Anonfiles.com Domain - DNS Client
def rule(event):
    # Detection Logic:
    # (EventID="3008" AND QueryName="*.anonfiles.com*")
    return True

def title(event):
    return "DNS Query for Anonfiles.com Domain - DNS Client"

