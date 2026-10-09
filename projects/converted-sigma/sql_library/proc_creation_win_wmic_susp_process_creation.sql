-- Title: Suspicious Process Created Via Wmic.EXE
-- ID: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-10-12
-- Tags: attack.execution, attack.t1047
-- Description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%process %' AND CommandLine ILIKE '%call %' AND CommandLine ILIKE '%create %') AND (CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%bitsadmin%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%cmd.exe /c %' OR CommandLine ILIKE '%cmd.exe /k %' OR CommandLine ILIKE '%cmd.exe /r %' OR CommandLine ILIKE '%cmd /c %' OR CommandLine ILIKE '%cmd /k %' OR CommandLine ILIKE '%cmd /r %' OR CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%pwsh%' OR CommandLine ILIKE '%certutil%' OR CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%wscript%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Local\\%' OR CommandLine ILIKE '%%temp%%' OR CommandLine ILIKE '%%tmp%%' OR CommandLine ILIKE '%%ProgramData%%' OR CommandLine ILIKE '%%appdata%%' OR CommandLine ILIKE '%%comspec%%' OR CommandLine ILIKE '%%localappdata%%'))
