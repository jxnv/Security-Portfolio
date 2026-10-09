# Title: Registry Persistence via Service in Safe Mode
# ID: 1547e27c-3974-43e2-a7d7-7f484fb928ec
# Status: test
# Level: high
# Author: frack113
# Date: 2022-04-04
# Tags: attack.stealth, attack.t1564.001
# Description: Detects the modification of the registry to allow a driver or service to persist in Safe Mode.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Registry Persistence via Service in Safe Mode
def rule(event):
    # Detection Logic:
    # (((TargetObject="*\\Control\\SafeBoot\\Minimal\\*" OR TargetObject="*\\Control\\SafeBoot\\Network\\*") AND TargetObject="*\\(Default)" AND Details="Service") AND NOT (((Image="C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe" AND (TargetObject="*\\Control\\SafeBoot\\Minimal\\Hexnode Updater\\(Default)" OR TargetObject="*\\Control\\SafeBoot\\Network\\Hexnode Updater\\(Default)" OR TargetObject="*\\Control\\SafeBoot\\Minimal\\Hexnode Agent\\(Default)" OR TargetObject="*\\Control\\SafeBoot\\Network\\Hexnode Agent\\(Default)") AND Details="Service") OR (Image="*\\MBAMInstallerService.exe" AND TargetObject="*\\MBAMService\\(Default)" AND Details="Service") OR (Image="C:\\WINDOWS\\system32\\msiexec.exe" AND (TargetObject="*\\Control\\SafeBoot\\Minimal\\SAVService\\(Default)" OR TargetObject="*\\Control\\SafeBoot\\Network\\SAVService\\(Default)")))))
    return True

def title(event):
    return "Registry Persistence via Service in Safe Mode"

