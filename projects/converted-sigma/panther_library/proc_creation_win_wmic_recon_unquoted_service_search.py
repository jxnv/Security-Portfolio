# Title: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
# ID: 68bcd73b-37ef-49cb-95fc-edc809730be6
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-20
# Tags: attack.execution, attack.t1047
# Description: Detects known WMI recon method to look for unquoted service paths using wmic. Often used by pentester and attacker enumeration scripts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* service get *" AND CommandLine="*name,displayname,pathname,startmode*")) AND ((OriginalFileName="wmic.exe") OR (Image="*\\WMIC.exe")))
    return True

def title(event):
    return "Potential Unquoted Service Path Reconnaissance Via Wmic.EXE"

