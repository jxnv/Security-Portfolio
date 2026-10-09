-- Title: Privilege Escalation via Named Pipe Impersonation
-- ID: 9bd04a79-dabe-4f1f-a5ff-92430265c96b
-- Status: test
-- Level: high
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-27
-- Tags: attack.lateral-movement, attack.t1021
-- Description: Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%echo%' AND CommandLine ILIKE '%>%' AND CommandLine ILIKE '%\\\\\\\\.\\\\pipe\\\\%')) AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell.exe')) OR ((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'PowerShell.EXE'))))
