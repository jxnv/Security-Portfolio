-- Title: Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load
-- ID: 48bfd177-7cf2-412b-ad77-baf923489e82
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2023-02-17
-- Tags: attack.impact, attack.t1490
-- Description: Detects the image load of VSS DLL by uncommon executables
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\vsstrace.dll') AND NOT (((Image IS NULL) OR ((Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%')) OR (((Image = 'C:\\Windows\\explorer.exe' OR Image = 'C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe' OR Image = 'C:\\Windows\\servicing\\TrustedInstaller.exe')) OR ((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\Temp\\{%' OR Image ILIKE 'C:\\Windows\\WinSxS\\%' OR Image ILIKE 'C:\\ProgramData\\Package Cache\\{%'))))) AND NOT ((((Image ILIKE '%\\temp\\is-%' AND Image ILIKE '%\\avira_system_speedup.tmp%')) OR (Image ILIKE 'C:\\$WinREAgent\\Scratch\\%'))))
