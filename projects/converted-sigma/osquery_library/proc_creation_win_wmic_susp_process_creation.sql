-- Title: Suspicious Process Created Via Wmic.EXE
-- ID: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-10-12
-- Tags: attack.execution, attack.t1047
-- Description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%process %' AND CommandLine LIKE '%call %' AND CommandLine LIKE '%create %') AND (CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%bitsadmin%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd.exe /r %' OR CommandLine LIKE '%cmd /c %' OR CommandLine LIKE '%cmd /k %' OR CommandLine LIKE '%cmd /r %' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%pwsh%' OR CommandLine LIKE '%certutil%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%wscript%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\%' OR CommandLine LIKE '%%temp%%' OR CommandLine LIKE '%%tmp%%' OR CommandLine LIKE '%%ProgramData%%' OR CommandLine LIKE '%%appdata%%' OR CommandLine LIKE '%%comspec%%' OR CommandLine LIKE '%%localappdata%%'))
