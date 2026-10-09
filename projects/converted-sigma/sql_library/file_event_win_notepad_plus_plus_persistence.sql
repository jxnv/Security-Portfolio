-- Title: Potential Persistence Via Notepad++ Plugins
-- ID: 54127bd4-f541-4ac3-afdb-ea073f63f692
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-10
-- Tags: attack.persistence
-- Description: Detects creation of new ".dll" files inside the plugins directory of a notepad++ installation by a process other than "gup.exe". Which could indicates possible persistence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetFilename ILIKE '%\\Notepad++\\plugins\\%' AND TargetFilename ILIKE '%.dll') AND NOT (((Image ILIKE '%\\Notepad++\\updater\\gup.exe') OR (Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Temp\\%' AND (Image ILIKE '%\\target.exe' OR Image ILIKE '%Installer.x64.exe')) OR (Image ILIKE '%\\npp.%' AND Image ILIKE '%.exe' AND (TargetFilename = 'C:\\Program Files\\Notepad++\\plugins\\NppExport\\NppExport.dll' OR TargetFilename = 'C:\\Program Files\\Notepad++\\plugins\\mimeTools\\mimeTools.dll' OR TargetFilename = 'C:\\Program Files\\Notepad++\\plugins\\NppConverter\\NppConverter.dll' OR TargetFilename = 'C:\\Program Files\\Notepad++\\plugins\\Config\\nppPluginList.dll')))))
