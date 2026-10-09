# Title: Alternate PowerShell Hosts Pipe
# ID: 58cb02d5-78ce-4692-b3e1-dce850aae41a
# Status: test
# Level: medium
# Author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
# Date: 2019-09-12
# Tags: attack.execution, attack.t1059.001
# Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Alternate PowerShell Hosts Pipe
def rule(event):
    # Detection Logic:
    # ((PipeName="\\PSHost*") AND NOT (((((Image="*:\\Program Files\\PowerShell\\7-preview\\pwsh.exe*" OR Image="*:\\Program Files\\PowerShell\\7\\pwsh.exe*" OR Image="*:\\Windows\\system32\\dsac.exe*" OR Image="*:\\Windows\\system32\\inetsrv\\w3wp.exe*" OR Image="*:\\Windows\\System32\\sdiagnhost.exe*" OR Image="*:\\Windows\\system32\\ServerManager.exe*" OR Image="*:\\Windows\\system32\\wbem\\wmiprvse.exe*" OR Image="*:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe*" OR Image="*:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe*" OR Image="*:\\Windows\\System32\\wsmprovhost.exe*" OR Image="*:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe*" OR Image="*:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe*")) OR ((Image="*C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview*" AND Image="*\\pwsh.exe*")) OR ((Image="*\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview*" AND Image="*\\pwsh.exe*"))) OR (NOT Image=*))) AND NOT (((Image="C:\\Program Files\\AzureConnectedMachineAgent\\GCArcService*" AND Image="*\\GC\\gc_worker.exe") OR (Image="C:\\Program Files\\Citrix\\*") OR (Image="C:\\Program Files\\Microsoft\\Exchange Server\\*") OR ((Image="C:\\Program Files (x86)\\*" OR Image="C:\\Program Files\\*") AND Image="*\\Microsoft SQL Server\\*" AND Image="*\\Tools\\Binn\\SQLPS.exe"))))
    return True

def title(event):
    return "Alternate PowerShell Hosts Pipe"

