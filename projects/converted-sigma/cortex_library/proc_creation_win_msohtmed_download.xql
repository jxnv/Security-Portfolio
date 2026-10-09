// Title: Arbitrary File Download Via MSOHTMED.EXE
// ID: 459f2f98-397b-4a4a-9f47-6a5ec2f1c69d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects usage of "MSOHTMED" to download arbitrary files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ftp://" or action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and ((action_process_image_path endswith "\\MSOHTMED.exe") or (action_process_image_name = "MsoHtmEd.exe")))
