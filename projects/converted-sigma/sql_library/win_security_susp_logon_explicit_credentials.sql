-- Title: Suspicious Remote Logon with Explicit Credentials
-- ID: 941e5c45-cda7-4864-8cea-bbb7458d194a
-- Status: test
-- Level: medium
-- Author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Tim Shelton
-- Date: 2020-10-05
-- Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.stealth, attack.t1078, attack.lateral-movement
-- Description: Detects suspicious processes logging on with explicit credentials
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((EventID = 4648 AND (ProcessName ILIKE '%\\cmd.exe' OR ProcessName ILIKE '%\\powershell.exe' OR ProcessName ILIKE '%\\pwsh.exe' OR ProcessName ILIKE '%\\winrs.exe' OR ProcessName ILIKE '%\\wmic.exe' OR ProcessName ILIKE '%\\net.exe' OR ProcessName ILIKE '%\\net1.exe' OR ProcessName ILIKE '%\\reg.exe')) AND NOT (((TargetServerName = 'localhost') OR (SubjectUserName ILIKE '%$' AND TargetUserName ILIKE '%$'))))
