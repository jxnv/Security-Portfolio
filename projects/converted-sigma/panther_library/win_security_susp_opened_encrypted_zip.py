# Title: Password Protected ZIP File Opened
# ID: 00ba9da1-b510-4f6b-b258-8d338836180f
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2022-05-09
# Tags: attack.stealth, attack.t1027
# Description: Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Password Protected ZIP File Opened
def rule(event):
    # Detection Logic:
    # ((EventID="5379" AND TargetName="*Microsoft_Windows_Shell_ZipFolder:filename*") AND NOT ((TargetName="*\\Temporary Internet Files\\Content.Outlook*")))
    return True

def title(event):
    return "Password Protected ZIP File Opened"

