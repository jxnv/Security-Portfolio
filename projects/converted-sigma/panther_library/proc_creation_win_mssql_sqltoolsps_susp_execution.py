# Title: SQL Client Tools PowerShell Session Detection
# ID: a746c9b8-a2fb-4ee5-a428-92bee9e99060
# Status: test
# Level: medium
# Author: Agro (@agro_sev) oscd.communitly
# Date: 2020-10-13
# Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1127
# Description: This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio.
# Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SQL Client Tools PowerShell Session Detection
def rule(event):
    # Detection Logic:
    # (((Image="*\\sqltoolsps.exe") OR (ParentImage="*\\sqltoolsps.exe") OR (OriginalFileName="\\sqltoolsps.exe")) AND NOT ((ParentImage="*\\smss.exe")))
    return True

def title(event):
    return "SQL Client Tools PowerShell Session Detection"

