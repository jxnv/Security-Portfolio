// Title: Permission Misconfiguration Reconnaissance Via Findstr.EXE
// ID: 47e4bab7-c626-47dc-967b-255608c9a920
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-12
// Tags: attack.credential-access, attack.t1552.006
// Description: Detects usage of findstr with the "EVERYONE" or "BUILTIN" keywords.
// This was seen being used in combination with "icacls" and other utilities to spot misconfigured files or folders permissions.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "\"Everyone\"" or action_process_image_command_line contains "'Everyone'" or action_process_image_command_line contains "\"BUILTIN\\\\\"" or action_process_image_command_line contains "'BUILTIN\\'")) and (((action_process_image_path endswith "\\find.exe" or action_process_image_path endswith "\\findstr.exe")) or ((action_process_image_name = "FIND.EXE" or action_process_image_name = "FINDSTR.EXE")))) or ((action_process_image_command_line contains "icacls " and action_process_image_command_line contains "findstr " and action_process_image_command_line contains "Everyone")))
