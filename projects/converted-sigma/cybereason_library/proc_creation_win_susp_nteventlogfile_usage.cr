// Title: Potentially Suspicious Call To Win32_NTEventlogFile Class
// ID: caf201a9-c2ce-4a26-9c3a-2b9525413711
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-13
// Tags: attack.defense-impairment
// Description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "Win32_NTEventlogFile") AND ((CommandLine contains ".BackupEventlog(" OR CommandLine contains ".ChangeSecurityPermissions(" OR CommandLine contains ".ChangeSecurityPermissionsEx(" OR CommandLine contains ".ClearEventLog(" OR CommandLine contains ".Delete(" OR CommandLine contains ".DeleteEx(" OR CommandLine contains ".Rename(" OR CommandLine contains ".TakeOwnerShip(" OR CommandLine contains ".TakeOwnerShipEx(")))
