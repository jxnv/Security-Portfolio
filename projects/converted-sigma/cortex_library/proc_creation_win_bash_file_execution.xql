// Title: Indirect Command Execution From Script File Via Bash.EXE
// ID: 2d22a514-e024-4428-9dba-41505bd63a5b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-15
// Tags: attack.stealth, attack.t1202
// Description: Detects execution of Microsoft bash launcher without any flags to execute the content of a bash script directly.
// This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith ":\\Windows\\System32\\bash.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\bash.exe")) or (action_process_image_name = "Bash.exe")) and not ((((action_process_image_command_line contains "bash.exe -" or action_process_image_command_line contains "bash -")) or (action_process_image_command_line = "") or (action_process_image_command_line = null) or ((action_process_image_command_line = "bash.exe" or action_process_image_command_line = "bash")))))
