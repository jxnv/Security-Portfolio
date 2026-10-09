-- Title: Suspicious MsiExec Embedding Parent
-- ID: 4a2a2c3e-209f-4d01-b513-4155a540b469
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-04-16
-- Tags: attack.stealth, attack.t1218.007
-- Description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\cmd.exe') AND (ParentCommandLine ILIKE '%MsiExec.exe%' AND ParentCommandLine ILIKE '%-Embedding %')) AND NOT (((Image ILIKE '%:\\Windows\\System32\\cmd.exe' AND CommandLine ILIKE '%C:\\Program Files\\SplunkUniversalForwarder\\bin\\%') OR ((CommandLine ILIKE '%\\DismFoDInstall.cmd%') OR ((ParentCommandLine ILIKE '%\\MsiExec.exe -Embedding %' AND ParentCommandLine ILIKE '%Global\\MSI0000%'))))))
