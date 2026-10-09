# Title: Potential Command Line Path Traversal Evasion Attempt
# ID: 1327381e-6ab0-4f38-b583-4c1b8346a56b
# Status: test
# Level: medium
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-10-26
# Tags: attack.stealth, attack.t1036
# Description: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Command Line Path Traversal Evasion Attempt
def rule(event):
    # Detection Logic:
    # (((Image="*\\Windows\\*" AND (CommandLine="*\\..\\Windows\\*" OR CommandLine="*\\..\\System32\\*" OR CommandLine="*\\..\\..\\*")) OR (CommandLine="*.exe\\..\\*")) AND NOT (((CommandLine="*\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\..\\*") OR (CommandLine="*\\Google\\Drive\\googledrivesync.exe\\..\\*"))))
    return True

def title(event):
    return "Potential Command Line Path Traversal Evasion Attempt"

