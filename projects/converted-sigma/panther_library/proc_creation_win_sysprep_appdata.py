# Title: Sysprep on AppData Folder
# ID: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2018-06-22
# Tags: attack.execution, attack.t1059
# Description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Sysprep on AppData Folder
def rule(event):
    # Detection Logic:
    # (Image="*\\sysprep.exe" AND CommandLine="*\\AppData\\*")
    return True

def title(event):
    return "Sysprep on AppData Folder"

