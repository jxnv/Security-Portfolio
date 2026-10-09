# Title: Enable Local Manifest Installation With Winget
# ID: fa277e82-9b78-42dd-b05c-05555c7b6015
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-04-17
# Tags: attack.persistence, attack.stealth
# Description: Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Enable Local Manifest Installation With Winget
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\AppInstaller\\EnableLocalManifestFiles" AND Details="DWORD (0x00000001)")
    return True

def title(event):
    return "Enable Local Manifest Installation With Winget"

