-- Title: Uncommon Svchost Command Line Parameter
-- ID: f17211f1-1f24-4d0c-829f-31e28dc93cdd
-- Status: experimental
-- Level: high
-- Author: Liran Ravich
-- Date: 2025-11-14
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1036.005, attack.t1055, attack.t1055.012
-- Description: Detects instances of svchost.exe running with an unusual or uncommon command line parameter by excluding known legitimate or common patterns.
-- This could point at a file masquerading as svchost, a process injection, or hollowing of a legitimate svchost instance.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\svchost.exe') AND NOT (((CommandLine = '') OR (REGEXP_LIKE(CommandLine, '-k\s\w{1,64}(?:\s?(?:-p|-s))?')) OR (CommandLine IS NULL))) AND NOT (((ParentImage ILIKE '%\\MsMpEng.exe' AND CommandLine ILIKE '%svchost.exe%') OR (ParentImage ILIKE '%\\MRT.exe' AND CommandLine = 'svchost.exe'))))
