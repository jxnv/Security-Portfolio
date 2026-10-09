# Title: New User Created Via Net.EXE
# ID: cd219ff3-fa99-45d4-8380-a7d15116c6dc
# Status: test
# Level: medium
# Author: Endgame, JHasenbusch (adapted to Sigma for oscd.community)
# Date: 2018-10-30
# Tags: attack.persistence, attack.t1136.001
# Description: Identifies the creation of local users via the net.exe command.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New User Created Via Net.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*user*" AND CommandLine="*add*")) AND (((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName="net.exe" OR OriginalFileName="net1.exe"))))
    return True

def title(event):
    return "New User Created Via Net.EXE"

