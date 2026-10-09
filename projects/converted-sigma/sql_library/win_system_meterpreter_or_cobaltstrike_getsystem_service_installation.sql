-- Title: Meterpreter or Cobalt Strike Getsystem Service Installation - System
-- ID: 843544a7-56e0-4dcc-a44f-5cc266dd97d6
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
-- Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Provider_Name = 'Service Control Manager' AND EventID = 7045) AND (((ImagePath ILIKE '%/c%' AND ImagePath ILIKE '%echo%' AND ImagePath ILIKE '%\\pipe\\%') AND (ImagePath ILIKE '%cmd%' OR ImagePath ILIKE '%%COMSPEC%%')) OR ((ImagePath ILIKE '%rundll32%' AND ImagePath ILIKE '%.dll,a%' AND ImagePath ILIKE '%/p:%')) OR (ImagePath ILIKE '\\\\\\\\127.0.0.1\\\\ADMIN$\\%')))
