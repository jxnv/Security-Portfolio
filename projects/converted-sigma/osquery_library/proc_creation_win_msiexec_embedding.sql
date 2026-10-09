-- Title: Suspicious MsiExec Embedding Parent
-- ID: 4a2a2c3e-209f-4d01-b513-4155a540b469
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-04-16
-- Tags: attack.stealth, attack.t1218.007
-- Description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe") AND (ParentCommandLine LIKE '%MsiExec.exe%' AND ParentCommandLine LIKE '%-Embedding %')) AND NOT (((Image="*:\\Windows\\System32\\cmd.exe" AND CommandLine LIKE '%C:\\Program Files\\SplunkUniversalForwarder\\bin\\%') OR ((CommandLine LIKE '%\\DismFoDInstall.cmd%') OR ((ParentCommandLine LIKE '%\\MsiExec.exe -Embedding %' AND ParentCommandLine LIKE '%Global\\MSI0000%'))))))
