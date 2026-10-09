// Title: Arbitrary File Download Via MSPUB.EXE
// ID: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ftp://" or action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and ((action_process_image_path endswith "\\MSPUB.exe") or (action_process_image_name = "MSPUB.exe")))
