# Title: Outgoing Logon with New Credentials
# ID: def8b624-e08f-4ae1-8612-1ba21190da6b
# Status: test
# Level: low
# Author: Max Altgelt (Nextron Systems)
# Date: 2022-04-06
# Tags: attack.lateral-movement, attack.t1550
# Description: Detects logon events that specify new credentials
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Outgoing Logon with New Credentials
def rule(event):
    # Detection Logic:
    # (EventID="4624" AND LogonType="9")
    return True

def title(event):
    return "Outgoing Logon with New Credentials"

