# Title: Potential Signing Bypass Via Windows Developer Features
# ID: a383dec4-deec-4e6e-913b-ed9249670848
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-11
# Tags: attack.stealth
# Description: Detects when a user enable developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Signing Bypass Via Windows Developer Features
def rule(event):
    # Detection Logic:
    # ((CommandLine="*TurnOnDeveloperFeatures*") AND ((Image="*\\SystemSettingsAdminFlows.exe") OR (OriginalFileName="SystemSettingsAdminFlows.EXE")) AND ((CommandLine="*DeveloperUnlock*" OR CommandLine="*EnableSideloading*")))
    return True

def title(event):
    return "Potential Signing Bypass Via Windows Developer Features"

