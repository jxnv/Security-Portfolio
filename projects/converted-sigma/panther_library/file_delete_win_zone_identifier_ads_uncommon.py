# Title: ADS Zone.Identifier Deleted By Uncommon Application
# ID: 3109530e-ab47-4cc6-a953-cac5ebcc93ae
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-09-04
# Tags: attack.stealth, attack.t1070.004
# Description: Detects the deletion of the "Zone.Identifier" ADS by an uncommon process. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: ADS Zone.Identifier Deleted By Uncommon Application
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*:Zone.Identifier") AND NOT (((Image="C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe" OR Image="C:\\Program Files\\PowerShell\\7\\pwsh.exe" OR Image="C:\\Windows\\explorer.exe" OR Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OR Image="C:\\Windows\\SysWOW64\\explorer.exe" OR Image="C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"))) AND NOT ((((Image="C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" OR Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")) OR ((Image="C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe" OR Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe")) OR ((Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" OR Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe")))))
    return True

def title(event):
    return "ADS Zone.Identifier Deleted By Uncommon Application"

