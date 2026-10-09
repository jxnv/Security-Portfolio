-- Title: Potential LSASS Process Dump Via Procdump
-- ID: 5afee48e-67dd-4e03-a783-f74259dcf998
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-10-30
-- Tags: attack.stealth, attack.t1036, attack.credential-access, attack.t1003.001, car.2013-05-009
-- Description: Detects potential credential harvesting attempts through LSASS memory dumps using ProcDump.
-- This rule identifies suspicious command-line patterns that combine memory dump flags (-ma, -mm, -mp) with LSASS-related process markers.
-- LSASS (Local Security Authority Subsystem Service) contains sensitive authentication data including plaintext passwords, NTLM hashes, and Kerberos tickets in memory.
-- Attackers commonly dump LSASS memory to extract credentials for lateral movement and privilege escalation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% -ma %' OR CommandLine ILIKE '% -mm %' OR CommandLine ILIKE '% -mp %')) AND ((CommandLine ILIKE '% ls%' OR CommandLine ILIKE '% keyiso%' OR CommandLine ILIKE '% samss%')))
