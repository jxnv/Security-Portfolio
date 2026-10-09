// Title: 7Zip Compressing Dump Files
// ID: ec570e53-4c76-45a9-804d-dc3f355ff7a7
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-27
// Tags: attack.collection, attack.t1560.001
// Description: Detects execution of 7z in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".dmp" or action_process_image_command_line contains ".dump" or action_process_image_command_line contains ".hdmp")) and ((Description contains "7-Zip") or ((action_process_image_path endswith "\\7z.exe" or action_process_image_path endswith "\\7zr.exe" or action_process_image_path endswith "\\7za.exe")) or ((action_process_image_name = "7z.exe" or action_process_image_name = "7za.exe" or action_process_image_name = "7zr.exe"))))
