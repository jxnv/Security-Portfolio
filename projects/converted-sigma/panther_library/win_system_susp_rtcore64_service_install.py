# Title: RTCore Suspicious Service Installation
# ID: 91c49341-e2ef-40c0-ac45-49ec5c3fe26c
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-30
# Tags: attack.persistence
# Description: Detects the installation of RTCore service. Which could be an indication of Micro-Star MSI Afterburner vulnerable driver abuse
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: RTCore Suspicious Service Installation
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND EventID="7045" AND ServiceName="RTCore64")
    return True

def title(event):
    return "RTCore Suspicious Service Installation"

