-- Title: Potential CobaltStrike Process Patterns
-- ID: f35c5d71-b489-4e22-a115-f003df287317
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-07-27
-- Tags: attack.execution, attack.t1059
-- Description: Detects potential process patterns related to Cobalt Strike beacon activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentCommandLine LIKE '%cmd.exe /C echo%' AND ParentCommandLine LIKE '% > \\\\\\\\.\\\\pipe%') AND CommandLine="*conhost.exe 0xffffffff -ForceV1") OR (ParentCommandLine="*/C whoami" AND CommandLine="*conhost.exe 0xffffffff -ForceV1") OR (CommandLine="*cmd.exe /C whoami" AND ParentImage="C:\\Temp\\*") OR ((ParentImage="*\\runonce.exe" OR ParentImage="*\\dllhost.exe") AND (CommandLine LIKE '%cmd.exe /c echo%' AND CommandLine LIKE '%> \\\\\\\\.\\\\pipe%')))
