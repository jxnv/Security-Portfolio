-- Title: Alternate PowerShell Hosts Pipe
-- ID: 58cb02d5-78ce-4692-b3e1-dce850aae41a
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
-- Date: 2019-09-12
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((PipeName="\\PSHost*") AND NOT (((((Image LIKE '%:\\Program Files\\PowerShell\\7-preview\\pwsh.exe%' OR Image LIKE '%:\\Program Files\\PowerShell\\7\\pwsh.exe%' OR Image LIKE '%:\\Windows\\system32\\dsac.exe%' OR Image LIKE '%:\\Windows\\system32\\inetsrv\\w3wp.exe%' OR Image LIKE '%:\\Windows\\System32\\sdiagnhost.exe%' OR Image LIKE '%:\\Windows\\system32\\ServerManager.exe%' OR Image LIKE '%:\\Windows\\system32\\wbem\\wmiprvse.exe%' OR Image LIKE '%:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe%' OR Image LIKE '%:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe%' OR Image LIKE '%:\\Windows\\System32\\wsmprovhost.exe%' OR Image LIKE '%:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe%' OR Image LIKE '%:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe%')) OR ((Image LIKE '%C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview%' AND Image LIKE '%\\pwsh.exe%')) OR ((Image LIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview%' AND Image LIKE '%\\pwsh.exe%'))) OR (NOT Image=*))) AND NOT (((Image="C:\\Program Files\\AzureConnectedMachineAgent\\GCArcService*" AND Image="*\\GC\\gc_worker.exe") OR (Image="C:\\Program Files\\Citrix\\*") OR (Image="C:\\Program Files\\Microsoft\\Exchange Server\\*") OR ((Image="C:\\Program Files (x86)\\*" OR Image="C:\\Program Files\\*") AND Image LIKE '%\\Microsoft SQL Server\\%' AND Image="*\\Tools\\Binn\\SQLPS.exe"))))
