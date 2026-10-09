-- Title: Potential Provlaunch.EXE Binary Proxy Execution Abuse
-- ID: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
-- Date: 2023-08-08
-- Tags: attack.stealth, attack.t1218
-- Description: Detects child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\provlaunch.exe') AND NOT ((((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((Image ILIKE '%:\\PerfLogs\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%\\AppData\\Temp\\%' OR Image ILIKE '%\\Windows\\System32\\Tasks\\%' OR Image ILIKE '%\\Windows\\Tasks\\%' OR Image ILIKE '%\\Windows\\Temp\\%')))))
