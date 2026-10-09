-- Title: Renamed ProcDump Execution
-- ID: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-11-18
-- Tags: attack.stealth, attack.t1036.003
-- Description: Detects the execution of a renamed ProcDump executable.
-- This often done by attackers or malware in order to evade defensive mechanisms.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((OriginalFileName = 'procdump') OR (((CommandLine ILIKE '% -ma %' OR CommandLine ILIKE '% -mp %')) AND (CommandLine ILIKE '% /accepteula%'))) AND NOT (((Image ILIKE '%\\procdump.exe' OR Image ILIKE '%\\procdump64.exe' OR Image ILIKE '%\\procdump64a.exe'))))
