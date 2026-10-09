-- Title: System Control Panel Item Loaded From Uncommon Location
-- ID: 2b140a5c-dc02-4bb8-b6b1-8bdb45714cde
-- Status: test
-- Level: high
-- Author: Anish Bogati
-- Date: 2024-01-09
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects image load events of system control panel items (.cpl) from uncommon or non-system locations that may indicate DLL sideloading or other abuse techniques.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ImageLoaded ILIKE '%\\appwiz.cpl' OR ImageLoaded ILIKE '%\\bthprops.cpl' OR ImageLoaded ILIKE '%\\hdwwiz.cpl')) AND NOT (((ImageLoaded ILIKE 'C:\\Windows\\Prefetch\\%' OR ImageLoaded ILIKE 'C:\\Windows\\System32\\%' OR ImageLoaded ILIKE 'C:\\Windows\\SysWOW64\\%' OR ImageLoaded ILIKE 'C:\\Windows\\WinSxS\\%'))))
