# Title: Potential Reconnaissance Activity Via GatherNetworkInfo.VBS
# ID: 575dce0c-8139-4e30-9295-1ee75969f7fe
# Status: test
# Level: medium
# Author: blueteamer8699
# Date: 2022-01-03
# Tags: attack.discovery, attack.execution, attack.t1615, attack.t1059.005
# Description: Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Reconnaissance Activity Via GatherNetworkInfo.VBS
def rule(event):
    # Detection Logic:
    # ((CommandLine="*gatherNetworkInfo.vbs*") AND (((Image="*\\cscript.exe" OR Image="*\\wscript.exe")) OR ((OriginalFileName="cscript.exe" OR OriginalFileName="wscript.exe"))))
    return True

def title(event):
    return "Potential Reconnaissance Activity Via GatherNetworkInfo.VBS"

