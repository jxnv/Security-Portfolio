# Title: Suspicious Execution of Shutdown to Log Out
# ID: ec290c06-9b6b-4338-8b6b-095c0f284f10
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-10-01
# Tags: attack.impact, attack.t1529
# Description: Detects the rare use of the command line tool shutdown to logoff a user
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Execution of Shutdown to Log Out
def rule(event):
    # Detection Logic:
    # (Image="*\\shutdown.exe" AND CommandLine="*/l*")
    return True

def title(event):
    return "Suspicious Execution of Shutdown to Log Out"

