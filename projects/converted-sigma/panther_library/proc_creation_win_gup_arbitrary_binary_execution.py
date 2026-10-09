# Title: Arbitrary Binary Execution Using GUP Utility
# ID: d65aee4d-2292-4cea-b832-83accd6cfa43
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-10
# Tags: attack.execution
# Description: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Arbitrary Binary Execution Using GUP Utility
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\gup.exe" AND Image="*\\explorer.exe") AND NOT (((Image="*\\explorer.exe" AND CommandLine="*\\Notepad++\\notepad++.exe*") OR (NOT CommandLine=*) OR (ParentImage="*\\Notepad++\\updater\\*"))))
    return True

def title(event):
    return "Arbitrary Binary Execution Using GUP Utility"

