# Title: Potential Configuration And Service Reconnaissance Via Reg.EXE
# ID: 970007b7-ce32-49d0-a4a4-fbef016950bd
# Status: test
# Level: medium
# Author: Timur Zinniatullin, oscd.community
# Date: 2019-10-21
# Tags: attack.discovery, attack.t1012, attack.t1007
# Description: Detects the usage of "reg.exe" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Configuration And Service Reconnaissance Via Reg.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="*query*") AND ((Image="*\\reg.exe") OR (OriginalFileName="reg.exe")) AND ((CommandLine="*currentVersion\\windows*" OR CommandLine="*winlogon\\*" OR CommandLine="*currentVersion\\shellServiceObjectDelayLoad*" OR CommandLine="*currentVersion\\run*" OR CommandLine="*currentVersion\\policies\\explorer\\run*" OR CommandLine="*currentcontrolset\\services*")))
    return True

def title(event):
    return "Potential Configuration And Service Reconnaissance Via Reg.EXE"

