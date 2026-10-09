# Title: Suspicious New-PSDrive to Admin Share
# ID: 1c563233-030e-4a07-af8c-ee0490a66d3a
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-08-13
# Tags: attack.lateral-movement, attack.t1021.002
# Description: Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious New-PSDrive to Admin Share
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*New-PSDrive*" AND ScriptBlockText="*-psprovider *" AND ScriptBlockText="*filesystem*" AND ScriptBlockText="*-root *" AND ScriptBlockText="*\\\\\\\\*" AND ScriptBlockText="*$*"))
    return True

def title(event):
    return "Suspicious New-PSDrive to Admin Share"

