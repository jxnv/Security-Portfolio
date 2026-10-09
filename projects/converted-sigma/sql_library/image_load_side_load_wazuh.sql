-- Title: Potential Wazuh Security Platform DLL Sideloading
-- ID: db77ce78-7e28-4188-9337-cf30e2b3ba9f
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-03-13
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL side loading of DLLs that are part of the Wazuh security platform
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%\\libwazuhshared.dll' OR ImageLoaded ILIKE '%\\libwinpthread-1.dll')) AND NOT (((ImageLoaded ILIKE 'C:\\Program Files\\%' OR ImageLoaded ILIKE 'C:\\Program Files (x86)\\%'))) AND NOT (((ImageLoaded ILIKE '%\\AppData\\Local\\%' OR ImageLoaded ILIKE '%\\ProgramData\\%') AND ImageLoaded ILIKE '%\\mingw64\\bin\\libwinpthread-1.dll')))
