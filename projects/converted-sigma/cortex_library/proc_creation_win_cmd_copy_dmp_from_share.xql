// Title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
// ID: 044ba588-dff4-4918-9808-3f95e8160606
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-27
// Tags: attack.credential-access
// Description: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "copy " and action_process_image_command_line contains " \\\\\\\\") and (action_process_image_command_line contains ".dmp" or action_process_image_command_line contains ".dump" or action_process_image_command_line contains ".hdmp")) and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")))
