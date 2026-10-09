# Title: Root Certificate Installed From Susp Locations
# ID: 5f6a601c-2ecb-498b-9c33-660362323afa
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-09
# Tags: attack.defense-impairment, attack.t1553.004
# Description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Root Certificate Installed From Susp Locations
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Import-Certificate*" AND CommandLine="* -FilePath *" AND CommandLine="*Cert:\\LocalMachine\\Root*") AND (CommandLine="*\\AppData\\Local\\Temp\\*" OR CommandLine="*:\\Windows\\TEMP\\*" OR CommandLine="*\\Desktop\\*" OR CommandLine="*\\Downloads\\*" OR CommandLine="*\\Perflogs\\*" OR CommandLine="*:\\Users\\Public\\*"))
    return True

def title(event):
    return "Root Certificate Installed From Susp Locations"

