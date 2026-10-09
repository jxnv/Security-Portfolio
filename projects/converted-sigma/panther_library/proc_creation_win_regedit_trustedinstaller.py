# Title: Regedit as Trusted Installer
# ID: 883835a7-df45-43e4-bf1d-4268768afda4
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-05-27
# Tags: attack.privilege-escalation, attack.t1548
# Description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Regedit as Trusted Installer
def rule(event):
    # Detection Logic:
    # (Image="*\\regedit.exe" AND (ParentImage="*\\TrustedInstaller.exe" OR ParentImage="*\\ProcessHacker.exe"))
    return True

def title(event):
    return "Regedit as Trusted Installer"

