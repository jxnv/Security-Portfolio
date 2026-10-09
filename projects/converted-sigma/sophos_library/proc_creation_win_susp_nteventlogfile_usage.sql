-- Title: Potentially Suspicious Call To Win32_NTEventlogFile Class
-- ID: caf201a9-c2ce-4a26-9c3a-2b9525413711
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-13
-- Tags: attack.defense-impairment
-- Description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%Win32_NTEventlogFile%') AND ((CommandLine ILIKE '%.BackupEventlog(%' OR CommandLine ILIKE '%.ChangeSecurityPermissions(%' OR CommandLine ILIKE '%.ChangeSecurityPermissionsEx(%' OR CommandLine ILIKE '%.ClearEventLog(%' OR CommandLine ILIKE '%.Delete(%' OR CommandLine ILIKE '%.DeleteEx(%' OR CommandLine ILIKE '%.Rename(%' OR CommandLine ILIKE '%.TakeOwnerShip(%' OR CommandLine ILIKE '%.TakeOwnerShipEx(%')))
