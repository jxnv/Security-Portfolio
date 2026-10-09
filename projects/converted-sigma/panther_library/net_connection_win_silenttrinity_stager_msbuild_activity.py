# Title: Silenttrinity Stager Msbuild Activity
# ID: 50e54b8d-ad73-43f8-96a1-5191685b17a4
# Status: test
# Level: high
# Author: Kiran kumar s, oscd.community
# Date: 2020-10-11
# Tags: attack.execution, attack.stealth, attack.t1127.001
# Description: Detects a possible remote connections to Silenttrinity c2
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Silenttrinity Stager Msbuild Activity
def rule(event):
    # Detection Logic:
    # ((Image="*\\msbuild.exe") AND ((DestinationPort="80" OR DestinationPort="443") AND Initiated="true"))
    return True

def title(event):
    return "Silenttrinity Stager Msbuild Activity"

