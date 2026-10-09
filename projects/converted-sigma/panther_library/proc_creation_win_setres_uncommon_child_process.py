# Title: Uncommon Child Process Of Setres.EXE
# ID: 835e75bf-4bfd-47a4-b8a6-b766cac8bcb7
# Status: test
# Level: high
# Author: @gott_cyber, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-12-11
# Tags: attack.stealth, attack.t1218, attack.t1202
# Description: Detects uncommon child process of Setres.EXE.
# Setres.EXE is a Windows server only process and tool that can be used to set the screen resolution.
# It can potentially be abused in order to launch any arbitrary file with a name containing the word "choice" from the current execution path.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon Child Process Of Setres.EXE
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\setres.exe" AND Image="*\\choice*") AND NOT (((Image="*C:\\Windows\\System32\\choice.exe" OR Image="*C:\\Windows\\SysWOW64\\choice.exe"))))
    return True

def title(event):
    return "Uncommon Child Process Of Setres.EXE"

