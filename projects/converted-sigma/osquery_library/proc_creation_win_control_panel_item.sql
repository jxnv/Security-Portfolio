-- Title: Control Panel Items
-- ID: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
-- Status: test
-- Level: high
-- Author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
-- Date: 2020-06-22
-- Tags: attack.privilege-escalation, attack.execution, attack.stealth, attack.t1218.002, attack.persistence, attack.t1546
-- Description: Detects the malicious use of a control panel item
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%add%' AND CommandLine LIKE '%CurrentVersion\\Control Panel\\CPLs%')) AND ((Image="*\\reg.exe") OR (OriginalFileName = 'reg.exe'))) OR ((CommandLine="*.cpl") AND NOT ((((CommandLine LIKE '%regsvr32 %' AND CommandLine LIKE '% /s %' AND CommandLine LIKE '%igfxCPL.cpl%')) OR ((CommandLine LIKE '%\\System32\\%' OR CommandLine LIKE '%%System%%' OR CommandLine LIKE '%|C:\\Windows\\system32|%'))))))
