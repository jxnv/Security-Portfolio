-- Title: Potentially Suspicious Call To Win32_NTEventlogFile Class
-- ID: caf201a9-c2ce-4a26-9c3a-2b9525413711
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-13
-- Tags: attack.defense-impairment
-- Description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%Win32_NTEventlogFile%') AND ((CommandLine LIKE '%.BackupEventlog(%' OR CommandLine LIKE '%.ChangeSecurityPermissions(%' OR CommandLine LIKE '%.ChangeSecurityPermissionsEx(%' OR CommandLine LIKE '%.ClearEventLog(%' OR CommandLine LIKE '%.Delete(%' OR CommandLine LIKE '%.DeleteEx(%' OR CommandLine LIKE '%.Rename(%' OR CommandLine LIKE '%.TakeOwnerShip(%' OR CommandLine LIKE '%.TakeOwnerShipEx(%')))
