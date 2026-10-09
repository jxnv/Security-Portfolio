# Title: File Encryption Using Gpg4win
# ID: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-08-09
# Tags: attack.execution
# Description: Detects usage of Gpg4win to encrypt files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: File Encryption Using Gpg4win
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -c *" AND CommandLine="*passphrase*")) AND (((Image="*\\gpg.exe" OR Image="*\\gpg2.exe")) OR (Description="GnuPG’s OpenPGP tool")))
    return True

def title(event):
    return "File Encryption Using Gpg4win"

