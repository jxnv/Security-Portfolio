# Title: Replace Desktop Wallpaper by Powershell
# ID: c5ac6a1e-9407-45f5-a0ce-ca9a0806a287
# Status: test
# Level: low
# Author: frack113
# Date: 2021-12-26
# Tags: attack.impact, attack.t1491.001
# Description: An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users.
# This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Replace Desktop Wallpaper by Powershell
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Get-ItemProperty*" AND ScriptBlockText="*Registry::*" AND ScriptBlockText="*HKEY_CURRENT_USER\\Control Panel\\Desktop\\*" AND ScriptBlockText="*WallPaper*")) OR (ScriptBlockText="*SystemParametersInfo(20,0,*,3)*"))
    return True

def title(event):
    return "Replace Desktop Wallpaper by Powershell"

