-- Title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
-- ID: 044ba588-dff4-4918-9808-3f95e8160606
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-27
-- Tags: attack.credential-access
-- Description: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%copy %' AND CommandLine LIKE '% \\\\\\\\%') AND (CommandLine LIKE '%.dmp%' OR CommandLine LIKE '%.dump%' OR CommandLine LIKE '%.hdmp%')) AND ((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe')))
