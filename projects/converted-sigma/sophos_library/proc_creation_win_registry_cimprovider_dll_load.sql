-- Title: DLL Execution Via Register-cimprovider.exe
-- ID: a2910908-e86f-4687-aeba-76a5f996e652
-- Status: test
-- Level: medium
-- Author: Ivan Dyachkov, Yulia Fomina, oscd.community
-- Date: 2020-10-07
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574
-- Description: Detects using register-cimprovider.exe to execute arbitrary dll file.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\register-cimprovider.exe' AND (CommandLine ILIKE '%-path%' AND CommandLine ILIKE '%dll%'))
