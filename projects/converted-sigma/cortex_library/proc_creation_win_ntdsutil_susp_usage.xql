// Title: Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe)
// ID: a58353df-af43-4753-bad0-cd83ef35eef5
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-14
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects execution of ntdsutil.exe to perform different actions such as restoring snapshots...etc.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "snapshot" and action_process_image_command_line contains "mount ")) or ((action_process_image_command_line contains "ac" and action_process_image_command_line contains " i" and action_process_image_command_line contains " ntds"))) and ((action_process_image_path endswith "\\ntdsutil.exe") or (action_process_image_name = "ntdsutil.exe")))
