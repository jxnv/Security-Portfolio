-- Title: Using SettingSyncHost.exe as LOLBin
-- ID: b2ddd389-f676-4ac4-845a-e00781a48e5f
-- Status: test
-- Level: high
-- Author: Anton Kutepov, oscd.community
-- Date: 2020-02-05
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.008
-- Description: Detects using SettingSyncHost.exe to run hijacked binary
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (NOT (((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%'))) AND ((ParentCommandLine ILIKE '%cmd.exe /c%' AND ParentCommandLine ILIKE '%RoamDiag.cmd%' AND ParentCommandLine ILIKE '%-outputpath%')))
