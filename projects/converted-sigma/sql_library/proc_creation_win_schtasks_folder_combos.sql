-- Title: Schtasks From Suspicious Folders
-- ID: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-04-15
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects scheduled task creations that have suspicious action command and folder combinations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%C:\\ProgramData\\%' OR CommandLine ILIKE '%%ProgramData%%')) AND ((CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%pwsh%' OR CommandLine ILIKE '%cmd /c %' OR CommandLine ILIKE '%cmd /k %' OR CommandLine ILIKE '%cmd /r %' OR CommandLine ILIKE '%cmd.exe /c %' OR CommandLine ILIKE '%cmd.exe /k %' OR CommandLine ILIKE '%cmd.exe /r %')) AND (CommandLine ILIKE '% /create %') AND ((Image ILIKE '%\\schtasks.exe') OR (OriginalFileName = 'schtasks.exe')))
