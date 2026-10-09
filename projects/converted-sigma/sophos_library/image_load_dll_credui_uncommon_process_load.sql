-- Title: CredUI.DLL Loaded By Uncommon Process
-- ID: 9ae01559-cf7e-4f8e-8e14-4c290a1b4784
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-10-20
-- Tags: attack.credential-access, attack.collection, attack.t1056.002
-- Description: Detects loading of "credui.dll" and related DLLs by an uncommon process. Attackers might leverage this DLL for potential use of "CredUIPromptForCredentials" or "CredUnPackAuthenticationBufferW".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((ImageLoaded ILIKE '%\\credui.dll' OR ImageLoaded ILIKE '%\\wincredui.dll')) OR ((OriginalFileName = 'credui.dll' OR OriginalFileName = 'wincredui.dll'))) AND NOT ((((Image = 'C:\\Windows\\explorer.exe' OR Image = 'C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe' OR Image = 'C:\\Windows\\regedit.exe')) OR ((Image ILIKE 'C:\\Program Files (x86)\\%' OR Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\SystemApps\\%')))) AND NOT (((Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\%') OR (Image ILIKE '%\\opera_autoupdate.exe') OR ((Image ILIKE '%\\procexp64.exe' OR Image ILIKE '%\\procexp64a.exe' OR Image ILIKE '%\\procexp.exe')) OR (Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Microsoft\\Teams\\%' AND Image ILIKE '%\\Teams.exe'))))
