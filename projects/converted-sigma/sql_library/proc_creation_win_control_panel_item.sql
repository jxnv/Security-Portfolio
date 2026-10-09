-- Title: Control Panel Items
-- ID: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
-- Status: test
-- Level: high
-- Author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
-- Date: 2020-06-22
-- Tags: attack.privilege-escalation, attack.execution, attack.stealth, attack.t1218.002, attack.persistence, attack.t1546
-- Description: Detects the malicious use of a control panel item
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%add%' AND CommandLine ILIKE '%CurrentVersion\\Control Panel\\CPLs%')) AND ((Image ILIKE '%\\reg.exe') OR (OriginalFileName = 'reg.exe'))) OR ((CommandLine ILIKE '%.cpl') AND NOT ((((CommandLine ILIKE '%regsvr32 %' AND CommandLine ILIKE '% /s %' AND CommandLine ILIKE '%igfxCPL.cpl%')) OR ((CommandLine ILIKE '%\\System32\\%' OR CommandLine ILIKE '%%System%%' OR CommandLine ILIKE '%|C:\\Windows\\system32|%'))))))
