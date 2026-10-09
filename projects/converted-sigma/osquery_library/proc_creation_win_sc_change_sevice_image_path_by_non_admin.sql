-- Title: Possible Privilege Escalation via Weak Service Permissions
-- ID: d937b75f-a665-4480-88a5-2f20e9f9b22a
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov
-- Date: 2019-10-26
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
-- Description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\sc.exe" AND (IntegrityLevel = 'Medium' OR IntegrityLevel = 'S-1-16-8192')) AND (((CommandLine LIKE '%config%' AND CommandLine LIKE '%binPath%')) OR ((CommandLine LIKE '%failure%' AND CommandLine LIKE '%command%'))))
