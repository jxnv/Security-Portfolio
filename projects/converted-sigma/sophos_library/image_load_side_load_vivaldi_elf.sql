-- Title: Potential Vivaldi_elf.DLL Sideloading
-- ID: 2092cacb-d77b-4f98-ab0d-32b32f99a054
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-08-03
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "vivaldi_elf.dll"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\vivaldi_elf.dll') AND NOT ((Image ILIKE '%\\Vivaldi\\Application\\vivaldi.exe' AND ImageLoaded ILIKE '%\\Vivaldi\\Application\\%')))
