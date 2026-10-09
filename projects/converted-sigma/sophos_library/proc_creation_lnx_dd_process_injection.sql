-- Title: Potential Linux Process Code Injection Via DD Utility
-- ID: 4cad6c64-d6df-42d6-8dae-eb78defdc415
-- Status: test
-- Level: medium
-- Author: Joseph Kamau
-- Date: 2023-12-01
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055.009
-- Description: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/dd' AND (CommandLine ILIKE '%of=%' AND CommandLine ILIKE '%/proc/%' AND CommandLine ILIKE '%/mem%'))
