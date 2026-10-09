// Title: Potentially Suspicious Call To Win32_NTEventlogFile Class
// ID: caf201a9-c2ce-4a26-9c3a-2b9525413711
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-13
// Tags: attack.defense-impairment
// Description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Win32_NTEventlogFile") and ((action_process_image_command_line contains ".BackupEventlog(" or action_process_image_command_line contains ".ChangeSecurityPermissions(" or action_process_image_command_line contains ".ChangeSecurityPermissionsEx(" or action_process_image_command_line contains ".ClearEventLog(" or action_process_image_command_line contains ".Delete(" or action_process_image_command_line contains ".DeleteEx(" or action_process_image_command_line contains ".Rename(" or action_process_image_command_line contains ".TakeOwnerShip(" or action_process_image_command_line contains ".TakeOwnerShipEx(")))
