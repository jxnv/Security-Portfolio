-- Title: Potential Meterpreter/CobaltStrike Activity
-- ID: 15619216-e993-4721-b590-4c520615a67d
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Ecco, Florian Roth
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
-- Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\services.exe") AND (((CommandLine LIKE '%/c%' AND CommandLine LIKE '%echo%' AND CommandLine LIKE '%\\pipe\\%') AND (CommandLine LIKE '%cmd%' OR CommandLine LIKE '%%COMSPEC%%')) OR ((CommandLine LIKE '%rundll32%' AND CommandLine LIKE '%.dll,a%' AND CommandLine LIKE '%/p:%'))) AND NOT ((CommandLine LIKE '%MpCmdRun%')))
