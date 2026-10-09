# Title: Installation of TeamViewer Desktop
# ID: 9711de76-5d4f-4c50-a94f-21e4e8f8384d
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-01-28
# Tags: attack.command-and-control, attack.t1219.002
# Description: TeamViewer_Desktop.exe is create during install
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Installation of TeamViewer Desktop
def rule(event):
    # Detection Logic:
    # (TargetFilename="*\\TeamViewer_Desktop.exe")
    return True

def title(event):
    return "Installation of TeamViewer Desktop"

