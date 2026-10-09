# Title: Devtoolslauncher.exe Executes Specified Binary
# ID: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
# Status: test
# Level: high
# Author: Beyu Denis, oscd.community (rule), @_felamos (idea)
# Date: 2019-10-12
# Tags: attack.stealth, attack.t1218
# Description: The Devtoolslauncher.exe executes other binary
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Devtoolslauncher.exe Executes Specified Binary
def rule(event):
    # Detection Logic:
    # (Image="*\\devtoolslauncher.exe" AND CommandLine="*LaunchForDeploy*")
    return True

def title(event):
    return "Devtoolslauncher.exe Executes Specified Binary"

