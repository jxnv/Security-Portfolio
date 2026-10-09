# Title: CurrentControlSet Autorun Keys Modification
# ID: f674e36a-4b91-431e-8aef-f8a96c2aca35
# Status: test
# Level: medium
# Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
# Date: 2019-10-25
# Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
# Description: Detects modification of autostart extensibility point (ASEP) in registry.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CurrentControlSet Autorun Keys Modification
def rule(event):
    # Detection Logic:
    # (((TargetObject="*\\SYSTEM\\CurrentControlSet\\Control*") AND ((TargetObject="*\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram*" OR TargetObject="*\\Terminal Server\\Wds\\rdpwd\\StartupPrograms*" OR TargetObject="*\\SecurityProviders\\SecurityProviders*" OR TargetObject="*\\SafeBoot\\AlternateShell*" OR TargetObject="*\\Print\\Providers*" OR TargetObject="*\\Print\\Monitors*" OR TargetObject="*\\NetworkProvider\\Order*" OR TargetObject="*\\Lsa\\Notification Packages*" OR TargetObject="*\\Lsa\\Authentication Packages*" OR TargetObject="*\\BootVerificationProgram\\ImagePath*"))) AND NOT (((Image="C:\\Windows\\System32\\spoolsv.exe" AND TargetObject="*\\Print\\Monitors\\CutePDF Writer Monitor*" AND (Details="cpwmon64_v40.dll" OR Details="CutePDF Writer")) OR (Details="(Empty)") OR (Image="C:\\Windows\\System32\\spoolsv.exe" AND TargetObject="*Print\\Monitors\\Appmon\\Ports\\Microsoft.Office.OneNote_*" AND (User="*AUTHORI*" OR User="*AUTORI*")) OR (Image="C:\\Windows\\System32\\poqexec.exe" AND TargetObject="*\\NetworkProvider\\Order\\ProviderOrder") OR (Image="C:\\Windows\\System32\\spoolsv.exe" AND TargetObject="*\\Print\\Monitors\\MONVNC\\Driver" AND Details="VNCpm.dll"))))
    return True

def title(event):
    return "CurrentControlSet Autorun Keys Modification"

