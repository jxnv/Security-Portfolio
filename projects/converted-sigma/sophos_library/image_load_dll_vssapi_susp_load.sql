-- Title: Suspicious Volume Shadow Copy Vssapi.dll Load
-- ID: 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-10-31
-- Tags: attack.impact, attack.t1490
-- Description: Detects the image load of VSS DLL by uncommon executables
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\vssapi.dll') AND NOT (((Image IS NULL) OR ((Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%')) OR (((Image = 'C:\\Windows\\explorer.exe' OR Image = 'C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe' OR Image = 'C:\\Windows\\servicing\\TrustedInstaller.exe')) OR ((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\Temp\\{%' OR Image ILIKE 'C:\\Windows\\WinSxS\\%' OR Image ILIKE 'C:\\$WinREAgent\\Scratch\\%'))))) AND NOT ((((Image ILIKE '%\\temp\\is-%' AND Image ILIKE '%\\avira_system_speedup.tmp%')) OR (Image ILIKE 'C:\\ProgramData\\Package Cache\\%'))))
