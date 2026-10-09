// Title: Potential Obfuscated Ordinal Call Via Rundll32
// ID: 43fa5350-db63-4b8f-9a01-789a427074e1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2023-05-17
// Tags: attack.stealth, attack.t1027.010
// Description: Detects execution of "rundll32" with potential obfuscated ordinal calls
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "#+" or action_process_image_command_line contains "#-" or action_process_image_command_line contains "#0" or action_process_image_command_line contains "#655" or action_process_image_command_line contains "#656")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE") or (action_process_image_command_line contains "rundll32")))
