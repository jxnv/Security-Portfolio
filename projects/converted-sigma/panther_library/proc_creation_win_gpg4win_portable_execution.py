# Title: Portable Gpg.EXE Execution
# ID: 77df53a5-1d78-4f32-bc5a-0e7465bd8f41
# Status: test
# Level: medium
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-08-06
# Tags: attack.impact, attack.t1486
# Description: Detects the execution of "gpg.exe" from uncommon location. Often used by ransomware and loaders to decrypt/encrypt data.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Portable Gpg.EXE Execution
def rule(event):
    # Detection Logic:
    # ((((Image="*\\gpg.exe" OR Image="*\\gpg2.exe")) OR (OriginalFileName="gpg.exe") OR (Description="GnuPG’s OpenPGP tool")) AND NOT (((Image="*:\\Program Files (x86)\\GNU\\GnuPG\\bin\\*" OR Image="*:\\Program Files (x86)\\GnuPG VS-Desktop\\*" OR Image="*:\\Program Files (x86)\\GnuPG\\bin\\*" OR Image="*:\\Program Files (x86)\\Gpg4win\\bin\\*"))))
    return True

def title(event):
    return "Portable Gpg.EXE Execution"

