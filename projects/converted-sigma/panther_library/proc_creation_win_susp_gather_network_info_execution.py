# Title: Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
# ID: 07aa184a-870d-413d-893a-157f317f6f58
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-02-08
# Tags: attack.discovery, attack.execution, attack.t1615, attack.t1059.005
# Description: Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
def rule(event):
    # Detection Logic:
    # ((CommandLine="*gatherNetworkInfo.vbs*") AND NOT (((Image="*\\cscript.exe" OR Image="*\\wscript.exe"))))
    return True

def title(event):
    return "Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS"

