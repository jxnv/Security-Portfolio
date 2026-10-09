# Title: Get-ADUser Enumeration Using UserAccountControl Flags
# ID: 96c982fe-3d08-4df4-bed2-eb14e02f21c8
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-03-17
# Tags: attack.discovery, attack.t1033
# Description: Detects AS-REP roasting is an attack that is often-overlooked. It is not very common as you have to explicitly set accounts that do not require pre-authentication.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Get-ADUser Enumeration Using UserAccountControl Flags
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Get-ADUser*" AND ScriptBlockText="*-Filter*" AND ScriptBlockText="*useraccountcontrol*" AND ScriptBlockText="*-band*" AND ScriptBlockText="*4194304*"))
    return True

def title(event):
    return "Get-ADUser Enumeration Using UserAccountControl Flags"

