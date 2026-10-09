-- Title: Non Interactive PowerShell Process Spawned
-- ID: f4bbd493-b796-416e-bbf2-121235348529
-- Status: test
-- Level: low
-- Author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
-- Date: 2019-09-12
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND NOT ((((ParentImage ILIKE '%:\\Windows\\explorer.exe' OR ParentImage ILIKE '%:\\Windows\\System32\\CompatTelRunner.exe' OR ParentImage ILIKE '%:\\Windows\\SysWOW64\\explorer.exe')) OR (ParentImage = ':\\$WINDOWS.~BT\\Sources\\SetupHost.exe'))) AND NOT (((ParentImage ILIKE '%:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseIR.exe') OR (ParentImage ILIKE '%:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_%' AND ParentImage ILIKE '%\\WindowsTerminal.exe') OR (ParentImage ILIKE '%\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe' AND ParentCommandLine ILIKE '% --ms-enable-electron-run-as-node %'))))
