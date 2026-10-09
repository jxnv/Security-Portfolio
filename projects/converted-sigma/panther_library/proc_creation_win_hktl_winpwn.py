# Title: HackTool - WinPwn Execution
# ID: d557dc06-62e8-4468-a8e8-7984124908ce
# Status: test
# Level: high
# Author: Swachchhanda Shrawan Poudel
# Date: 2023-12-04
# Tags: attack.credential-access, attack.discovery, attack.execution, attack.privilege-escalation, attack.t1046, attack.t1082, attack.t1106, attack.t1518, attack.t1548.002, attack.t1552.001, attack.t1555, attack.t1555.003
# Description: Detects commandline keywords indicative of potential usge of the tool WinPwn. A tool for Windows and Active Directory reconnaissance and exploitation.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - WinPwn Execution
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Offline_Winpwn*" OR CommandLine="*WinPwn *" OR CommandLine="*WinPwn.exe*" OR CommandLine="*WinPwn.ps1*"))
    return True

def title(event):
    return "HackTool - WinPwn Execution"

