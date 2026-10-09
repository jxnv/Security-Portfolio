-- Title: Meterpreter or Cobalt Strike Getsystem Service Installation - Security
-- ID: ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
-- Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 4697) AND (((ServiceFileName ILIKE '%/c%' AND ServiceFileName ILIKE '%echo%' AND ServiceFileName ILIKE '%\\pipe\\%') AND (ServiceFileName ILIKE '%cmd%' OR ServiceFileName ILIKE '%%COMSPEC%%')) OR ((ServiceFileName ILIKE '%rundll32%' AND ServiceFileName ILIKE '%.dll,a%' AND ServiceFileName ILIKE '%/p:%')) OR (ServiceFileName ILIKE '\\\\\\\\127.0.0.1\\\\ADMIN$\\%')))
