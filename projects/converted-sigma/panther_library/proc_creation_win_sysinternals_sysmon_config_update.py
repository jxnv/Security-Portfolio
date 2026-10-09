# Title: Sysmon Configuration Update
# ID: 87911521-7098-470b-a459-9a57fc80bdfd
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-03-09
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Sysmon Configuration Update
def rule(event):
    # Detection Logic:
    # (((CommandLine="*-c*" OR CommandLine="*/c*")) AND (((Image="*\\Sysmon64.exe" OR Image="*\\Sysmon64a.exe" OR Image="*\\Sysmon.exe")) OR (Description="System activity monitor")))
    return True

def title(event):
    return "Sysmon Configuration Update"

