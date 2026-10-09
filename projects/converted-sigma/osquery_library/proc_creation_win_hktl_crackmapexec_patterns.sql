-- Title: HackTool - CrackMapExec Process Patterns
-- ID: f26307d8-14cd-47e3-a26b-4b4769f24af6
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-12
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects suspicious process patterns found in logs when CrackMapExec is used
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%tasklist /fi %' AND CommandLine LIKE '%Imagename eq lsass.exe%') AND (CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd.exe /r %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd /c %' OR CommandLine LIKE '%cmd /r %' OR CommandLine LIKE '%cmd /k %') AND (User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%')) OR ((CommandLine LIKE '%do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump%' AND CommandLine LIKE '%\\Windows\\Temp\\%' AND CommandLine LIKE '% full%' AND CommandLine LIKE '%%%B%')) OR ((CommandLine LIKE '%tasklist /v /fo csv%' AND CommandLine LIKE '%findstr /i \"lsass\"%')))
