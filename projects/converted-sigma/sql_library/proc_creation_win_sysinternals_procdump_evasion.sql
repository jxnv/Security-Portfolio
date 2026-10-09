-- Title: Potential SysInternals ProcDump Evasion
-- ID: 79b06761-465f-4f88-9ef2-150e24d3d737
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-11
-- Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
-- Description: Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%copy procdump%' OR CommandLine ILIKE '%move procdump%')) OR ((CommandLine ILIKE '%copy %' AND CommandLine ILIKE '%.dmp %') AND (CommandLine ILIKE '%2.dmp%' OR CommandLine ILIKE '%lsass%' OR CommandLine ILIKE '%out.dmp%')) OR ((CommandLine ILIKE '%copy lsass.exe_%' OR CommandLine ILIKE '%move lsass.exe_%')))
