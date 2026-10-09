-- Title: Schtasks From Suspicious Folders
-- ID: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-04-15
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects scheduled task creations that have suspicious action command and folder combinations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%C:\\ProgramData\\%' OR CommandLine LIKE '%%ProgramData%%')) AND ((CommandLine LIKE '%powershell%' OR CommandLine LIKE '%pwsh%' OR CommandLine LIKE '%cmd /c %' OR CommandLine LIKE '%cmd /k %' OR CommandLine LIKE '%cmd /r %' OR CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd.exe /r %')) AND (CommandLine LIKE '% /create %') AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')))
