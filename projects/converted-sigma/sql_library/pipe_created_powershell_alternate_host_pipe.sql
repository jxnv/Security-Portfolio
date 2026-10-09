-- Title: Alternate PowerShell Hosts Pipe
-- ID: 58cb02d5-78ce-4692-b3e1-dce850aae41a
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
-- Date: 2019-09-12
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((PipeName ILIKE '\\PSHost%') AND NOT (((((Image ILIKE '%:\\Program Files\\PowerShell\\7-preview\\pwsh.exe%' OR Image ILIKE '%:\\Program Files\\PowerShell\\7\\pwsh.exe%' OR Image ILIKE '%:\\Windows\\system32\\dsac.exe%' OR Image ILIKE '%:\\Windows\\system32\\inetsrv\\w3wp.exe%' OR Image ILIKE '%:\\Windows\\System32\\sdiagnhost.exe%' OR Image ILIKE '%:\\Windows\\system32\\ServerManager.exe%' OR Image ILIKE '%:\\Windows\\system32\\wbem\\wmiprvse.exe%' OR Image ILIKE '%:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe%' OR Image ILIKE '%:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe%' OR Image ILIKE '%:\\Windows\\System32\\wsmprovhost.exe%' OR Image ILIKE '%:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe%' OR Image ILIKE '%:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe%')) OR ((Image ILIKE '%C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview%' AND Image ILIKE '%\\pwsh.exe%')) OR ((Image ILIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview%' AND Image ILIKE '%\\pwsh.exe%'))) OR (Image IS NULL))) AND NOT (((Image ILIKE 'C:\\Program Files\\AzureConnectedMachineAgent\\GCArcService%' AND Image ILIKE '%\\GC\\gc_worker.exe') OR (Image ILIKE 'C:\\Program Files\\Citrix\\%') OR (Image ILIKE 'C:\\Program Files\\Microsoft\\Exchange Server\\%') OR ((Image ILIKE 'C:\\Program Files (x86)\\%' OR Image ILIKE 'C:\\Program Files\\%') AND Image ILIKE '%\\Microsoft SQL Server\\%' AND Image ILIKE '%\\Tools\\Binn\\SQLPS.exe'))))
