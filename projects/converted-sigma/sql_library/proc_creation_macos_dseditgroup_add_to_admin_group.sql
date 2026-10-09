-- Title: User Added To Admin Group Via DseditGroup
-- ID: 5d0fdb62-f225-42fb-8402-3dfe64da468a
-- Status: test
-- Level: medium
-- Author: Sohan G (D4rkCiph3r)
-- Date: 2023-08-22
-- Tags: attack.persistence, attack.initial-access, attack.privilege-escalation, attack.stealth, attack.t1078.003
-- Description: Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%/dseditgroup' AND (CommandLine ILIKE '% -o edit %' AND CommandLine ILIKE '% -a %' AND CommandLine ILIKE '% -t user%' AND CommandLine ILIKE '%admin%'))
