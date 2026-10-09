# Title: Sysmon Application Crashed
# ID: 4d7f1827-1637-4def-8d8a-fd254f9454df
# Status: test
# Level: high
# Author: Tim Shelton
# Date: 2022-04-26
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects application popup reporting a failure of the Sysmon service
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Sysmon Application Crashed
def rule(event):
    # Detection Logic:
    # (Provider_Name="Application Popup" AND EventID="26" AND (Caption="sysmon64.exe - Application Error" OR Caption="sysmon.exe - Application Error"))
    return True

def title(event):
    return "Sysmon Application Crashed"

