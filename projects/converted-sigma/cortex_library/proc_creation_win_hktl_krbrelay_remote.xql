// Title: HackTool - RemoteKrbRelay Execution
// ID: a7664b14-75fb-4a50-a223-cb9bc0afbacf
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-06-27
// Tags: attack.credential-access, attack.t1558.003
// Description: Detects the use of RemoteKrbRelay, a Kerberos relaying tool via CommandLine flags and PE metadata.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\RemoteKrbRelay.exe") or (action_process_image_name = "RemoteKrbRelay.exe")) or ((action_process_image_command_line contains " -clsid " and action_process_image_command_line contains " -target " and action_process_image_command_line contains " -victim ")) or ((action_process_image_command_line contains "-rbcd ") and ((action_process_image_command_line contains "-cn " or action_process_image_command_line contains "--computername "))) or (action_process_image_command_line contains "-chp " and (action_process_image_command_line contains "-chpPass " and action_process_image_command_line contains "-chpUser ")) or ((action_process_image_command_line contains "-addgroupmember " and action_process_image_command_line contains "-group " and action_process_image_command_line contains "-groupuser ")) or ((action_process_image_command_line contains "-smb " and action_process_image_command_line contains "--smbkeyword ") and (action_process_image_command_line contains "interactive" or action_process_image_command_line contains "secrets" or action_process_image_command_line contains "service-add")))
