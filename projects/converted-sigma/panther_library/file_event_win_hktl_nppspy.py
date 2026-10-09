# Title: HackTool - NPPSpy Hacktool Usage
# ID: cad1fe90-2406-44dc-bd03-59d0b58fe722
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-11-29
# Tags: attack.credential-access
# Description: Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - NPPSpy Hacktool Usage
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*\\NPPSpy.txt" OR TargetFilename="*\\NPPSpy.dll"))
    return True

def title(event):
    return "HackTool - NPPSpy Hacktool Usage"

