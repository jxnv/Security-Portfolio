# Title: Remote Thread Created In KeePass.EXE
# ID: 77564cc2-7382-438b-a7f6-395c2ae53b9a
# Status: test
# Level: high
# Author: Timon Hackenjos
# Date: 2022-04-22
# Tags: attack.credential-access, attack.t1555.005
# Description: Detects remote thread creation in "KeePass.exe" which could indicates potential password dumping activity
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Thread Created In KeePass.EXE
def rule(event):
    # Detection Logic:
    # (TargetImage="*\\KeePass.exe")
    return True

def title(event):
    return "Remote Thread Created In KeePass.EXE"

