-- Title: Suspicious Child Process Of SQL Server
-- ID: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
-- Status: test
-- Level: high
-- Author: FPT.EagleEye Team, wagga
-- Date: 2020-12-11
-- Tags: attack.t1505.003, attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\sqlservr.exe' AND (Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\netstat.exe' OR Image ILIKE '%\\nltest.exe' OR Image ILIKE '%\\ping.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\systeminfo.exe' OR Image ILIKE '%\\tasklist.exe' OR Image ILIKE '%\\wsl.exe')) AND NOT ((ParentImage ILIKE 'C:\\Program Files\\Microsoft SQL Server\\%' AND ParentImage ILIKE '%DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe' AND Image = 'C:\\Windows\\System32\\cmd.exe' AND CommandLine ILIKE '\"C:\\Windows\\system32\\cmd.exe\" %')))
