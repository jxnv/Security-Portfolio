# Title: HackTool - Potential Impacket Lateral Movement Activity
# ID: 10c14723-61c7-4c75-92ca-9af245723ad2
# Status: stable
# Level: high
# Author: Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch
# Date: 2019-09-03
# Tags: attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.003
# Description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Potential Impacket Lateral Movement Activity
def rule(event):
    # Detection Logic:
    # (((ParentCommandLine="*svchost.exe -k netsvcs*" OR ParentCommandLine="*taskeng.exe*") AND (CommandLine="*cmd.exe*" AND CommandLine="*/C*" AND CommandLine="*Windows\\Temp\\*" AND CommandLine="*&1*")) OR ((ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\mmc.exe" OR ParentImage="*\\explorer.exe" OR ParentImage="*\\services.exe") AND (CommandLine="*cmd.exe*" AND CommandLine="*/Q*" AND CommandLine="*/c*" AND CommandLine="*\\\\\\\\127.0.0.1\\\\*" AND CommandLine="*&1*")))
    return True

def title(event):
    return "HackTool - Potential Impacket Lateral Movement Activity"

