# Title: Modify Group Policy Settings
# ID: ada4b0c4-758b-46ac-9033-9004613a150d
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-08-19
# Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
# Description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Modify Group Policy Settings
def rule(event):
    # Detection Logic:
    # (((CommandLine="*GroupPolicyRefreshTimeDC*" OR CommandLine="*GroupPolicyRefreshTimeOffsetDC*" OR CommandLine="*GroupPolicyRefreshTime*" OR CommandLine="*GroupPolicyRefreshTimeOffset*" OR CommandLine="*EnableSmartScreen*" OR CommandLine="*ShellSmartScreenLevel*")) AND (CommandLine="*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System*") AND ((Image="*\\reg.exe") OR (OriginalFileName="reg.exe")))
    return True

def title(event):
    return "Modify Group Policy Settings"

