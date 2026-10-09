-- Title: Potential Waveedit.DLL Sideloading
-- ID: 71b31e99-9ad0-47d4-aeb5-c0ca3928eeeb
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-06-14
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "waveedit.dll", which is part of the Nero WaveEditor audio editing software.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\waveedit.dll') AND NOT (((Image = 'C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe' OR Image = 'C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe') AND (ImageLoaded ILIKE 'C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\%'))))
