-- Title: Meterpreter or Cobalt Strike Getsystem Service Installation - Security
-- ID: ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
-- Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '4697') AND (((ServiceFileName LIKE '%/c%' AND ServiceFileName LIKE '%echo%' AND ServiceFileName LIKE '%\\pipe\\%') AND (ServiceFileName LIKE '%cmd%' OR ServiceFileName LIKE '%%COMSPEC%%')) OR ((ServiceFileName LIKE '%rundll32%' AND ServiceFileName LIKE '%.dll,a%' AND ServiceFileName LIKE '%/p:%')) OR (ServiceFileName="\\\\\\\\127.0.0.1\\\\ADMIN$\\*")))
