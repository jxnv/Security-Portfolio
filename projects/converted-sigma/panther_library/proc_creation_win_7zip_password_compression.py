# Title: Compress Data and Lock With Password for Exfiltration With 7-ZIP
# ID: 9fbf5927-5261-4284-a71d-f681029ea574
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-07-27
# Tags: attack.collection, attack.t1560.001
# Description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Compress Data and Lock With Password for Exfiltration With 7-ZIP
def rule(event):
    # Detection Logic:
    # (((CommandLine="* a *" OR CommandLine="* u *")) AND ((Description="*7-Zip*") OR ((Image="*\\7z.exe" OR Image="*\\7zr.exe" OR Image="*\\7za.exe")) OR ((OriginalFileName="7z.exe" OR OriginalFileName="7za.exe" OR OriginalFileName="7zr.exe"))) AND (CommandLine="* -p*"))
    return True

def title(event):
    return "Compress Data and Lock With Password for Exfiltration With 7-ZIP"

