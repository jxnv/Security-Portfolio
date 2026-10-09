# Title: DHCP Server Loaded the CallOut DLL
# ID: 13fc89a9-971e-4ca6-b9dc-aa53a445bf40
# Status: test
# Level: high
# Author: Dimitrios Slamaris
# Date: 2017-05-15
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
# Description: This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DHCP Server Loaded the CallOut DLL
def rule(event):
    # Detection Logic:
    # (EventID="1033" AND Provider_Name="Microsoft-Windows-DHCP-Server")
    return True

def title(event):
    return "DHCP Server Loaded the CallOut DLL"

