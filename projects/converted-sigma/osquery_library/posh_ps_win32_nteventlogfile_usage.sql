-- Title: Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript
-- ID: e2812b49-bae0-4b21-b366-7c142eafcde2
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-13
-- Tags: attack.defense-impairment
-- Description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%Win32_NTEventlogFile%') AND ((ScriptBlockText LIKE '%.BackupEventlog(%' OR ScriptBlockText LIKE '%.ChangeSecurityPermissions(%' OR ScriptBlockText LIKE '%.ChangeSecurityPermissionsEx(%' OR ScriptBlockText LIKE '%.ClearEventLog(%' OR ScriptBlockText LIKE '%.Delete(%' OR ScriptBlockText LIKE '%.DeleteEx(%' OR ScriptBlockText LIKE '%.Rename(%' OR ScriptBlockText LIKE '%.TakeOwnerShip(%' OR ScriptBlockText LIKE '%.TakeOwnerShipEx(%')))
