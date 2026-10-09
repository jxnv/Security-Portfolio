-- Title: Potential CobaltStrike Process Patterns
-- ID: f35c5d71-b489-4e22-a115-f003df287317
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-07-27
-- Tags: attack.execution, attack.t1059
-- Description: Detects potential process patterns related to Cobalt Strike beacon activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentCommandLine ILIKE '%cmd.exe /C echo%' AND ParentCommandLine ILIKE '% > \\\\\\\\.\\\\pipe%') AND CommandLine ILIKE '%conhost.exe 0xffffffff -ForceV1') OR (ParentCommandLine ILIKE '%/C whoami' AND CommandLine ILIKE '%conhost.exe 0xffffffff -ForceV1') OR (CommandLine ILIKE '%cmd.exe /C whoami' AND ParentImage ILIKE 'C:\\Temp\\%') OR ((ParentImage ILIKE '%\\runonce.exe' OR ParentImage ILIKE '%\\dllhost.exe') AND (CommandLine ILIKE '%cmd.exe /c echo%' AND CommandLine ILIKE '%> \\\\\\\\.\\\\pipe%')))
