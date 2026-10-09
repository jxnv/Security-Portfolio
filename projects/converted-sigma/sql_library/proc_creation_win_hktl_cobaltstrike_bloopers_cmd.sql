-- Title: Operator Bloopers Cobalt Strike Commands
-- ID: 647c7b9e-d784-4fda-b9a0-45c565a7b729
-- Status: test
-- Level: high
-- Author: _pete_0, TheDFIRReport
-- Date: 2022-05-06
-- Tags: attack.execution, attack.t1059.003, stp.1u
-- Description: Detects use of Cobalt Strike commands accidentally entered in the CMD shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE 'cmd %' OR CommandLine ILIKE 'cmd.exe%' OR CommandLine ILIKE 'c:\\windows\\system32\\cmd.exe%') AND (CommandLine ILIKE '%psinject%' OR CommandLine ILIKE '%spawnas%' OR CommandLine ILIKE '%make_token%' OR CommandLine ILIKE '%remote-exec%' OR CommandLine ILIKE '%rev2self%' OR CommandLine ILIKE '%dcsync%' OR CommandLine ILIKE '%logonpasswords%' OR CommandLine ILIKE '%execute-assembly%' OR CommandLine ILIKE '%getsystem%')) AND ((OriginalFileName = 'Cmd.Exe') OR (Image ILIKE '%\\cmd.exe')))
