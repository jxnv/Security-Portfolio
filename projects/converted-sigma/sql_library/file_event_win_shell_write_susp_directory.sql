-- Title: Windows Shell/Scripting Application File Write to Suspicious Folder
-- ID: 1277f594-a7d1-4f28-a2d3-73af5cbeab43
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-11-20
-- Tags: attack.execution, attack.t1059
-- Description: Detects Windows shells and scripting applications that write files to suspicious folders
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\msbuild.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\wscript.exe') AND (TargetFilename ILIKE 'C:\\PerfLogs\\%' OR TargetFilename ILIKE 'C:\\Users\\Public\\%')) OR ((Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\forfiles.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\scriptrunner.exe' OR Image ILIKE '%\\wmic.exe') AND (TargetFilename ILIKE '%C:\\PerfLogs\\%' OR TargetFilename ILIKE '%C:\\Users\\Public\\%' OR TargetFilename ILIKE '%C:\\Windows\\Temp\\%')))
