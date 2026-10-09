-- Title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
-- ID: 044ba588-dff4-4918-9808-3f95e8160606
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-27
-- Tags: attack.credential-access
-- Description: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%copy %' AND CommandLine ILIKE '% \\\\\\\\%') AND (CommandLine ILIKE '%.dmp%' OR CommandLine ILIKE '%.dump%' OR CommandLine ILIKE '%.hdmp%')) AND ((Image ILIKE '%\\cmd.exe') OR (OriginalFileName = 'Cmd.Exe')))
