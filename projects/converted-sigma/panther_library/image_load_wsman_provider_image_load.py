# Title: Suspicious WSMAN Provider Image Loads
# ID: ad1f4bb9-8dfb-4765-adb6-2a7cfb6c0f94
# Status: test
# Level: medium
# Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
# Date: 2020-06-24
# Tags: attack.execution, attack.t1059.001, attack.lateral-movement, attack.t1021.003
# Description: Detects signs of potential use of the WSMAN provider from uncommon processes locally and remote execution.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious WSMAN Provider Image Loads
def rule(event):
    # Detection Logic:
    # (((((ImageLoaded="*\\WsmSvc.dll" OR ImageLoaded="*\\WsmAuto.dll" OR ImageLoaded="*\\Microsoft.WSMan.Management.ni.dll")) OR ((OriginalFileName="WsmSvc.dll" OR OriginalFileName="WSMANAUTOMATION.DLL" OR OriginalFileName="Microsoft.WSMan.Management.dll"))) OR (Image="*\\svchost.exe" AND OriginalFileName="WsmWmiPl.dll")) AND NOT (((Image="C:\\Program Files\\Citrix\\*") OR ((Image="C:\\Program Files (x86)\\PowerShell\\6\\pwsh.exe" OR Image="C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe" OR Image="C:\\Program Files\\PowerShell\\6\\pwsh.exe" OR Image="C:\\Program Files\\PowerShell\\7\\pwsh.exe" OR Image="C:\\Windows\\System32\\sdiagnhost.exe" OR Image="C:\\Windows\\System32\\services.exe" OR Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" OR Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")) OR (Image="C:\\Program Files\\WindowsApps\\Microsoft.GetHelp_*" AND Image="*\\GetHelp.exe") OR (Image="*\\mmc.exe") OR ((Image="C:\\Windows\\Microsoft.NET\\Framework64\\v*" OR Image="C:\\Windows\\Microsoft.NET\\Framework\\v*" OR Image="C:\\Windows\\Microsoft.NET\\FrameworkArm\\v*" OR Image="C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v*") AND Image="*\\mscorsvw.exe") OR (Image="C:\\Windows\\Temp\\asgard2-agent\\*") OR ((CommandLine="*svchost.exe -k netsvcs -p -s BITS*" OR CommandLine="*svchost.exe -k GraphicsPerfSvcGroup -s GraphicsPerfSvc*" OR CommandLine="*svchost.exe -k NetworkService -p -s Wecsvc*" OR CommandLine="*svchost.exe -k netsvcs*")) OR ((Image="C:\\Windows\\System32\\Configure-SMRemoting.exe" OR Image="C:\\Windows\\System32\\ServerManager.exe")) OR (Image="C:\\$WINDOWS.~BT\\Sources\\*"))) AND NOT (((Image="*\\svchost.exe") AND (NOT CommandLine=*))))
    return True

def title(event):
    return "Suspicious WSMAN Provider Image Loads"

