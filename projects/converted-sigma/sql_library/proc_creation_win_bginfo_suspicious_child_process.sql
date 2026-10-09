-- Title: Suspicious Child Process Of BgInfo.EXE
-- ID: 811f459f-9231-45d4-959a-0266c6311987
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-16
-- Tags: attack.execution, attack.stealth, attack.t1059.005, attack.t1218, attack.t1202
-- Description: Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wscript.exe')) OR ((Image ILIKE '%\\AppData\\Local\\%' OR Image ILIKE '%\\AppData\\Roaming\\%' OR Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%:\\Windows\\Temp\\%' OR Image ILIKE '%:\\PerfLogs\\%'))) AND ((ParentImage ILIKE '%\\bginfo.exe' OR ParentImage ILIKE '%\\bginfo64.exe')))
