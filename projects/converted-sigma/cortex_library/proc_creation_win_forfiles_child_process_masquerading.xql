// Title: Forfiles.EXE Child Process Masquerading
// ID: f53714ec-5077-420e-ad20-907ff9bb2958
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Anish Bogati
// Date: 2024-01-05
// Tags: attack.stealth, attack.t1036
// Description: Detects the execution of "forfiles" from a non-default location, in order to potentially spawn a custom "cmd.exe" from the current working directory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line endswith ".exe" or actor_process_command_line endswith ".exe\"") and action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line startswith "/c echo \"") and not (((actor_process_image_path contains ":\\Windows\\System32\\" or actor_process_image_path contains ":\\Windows\\SysWOW64\\") and actor_process_image_path endswith "\\forfiles.exe" and (action_process_image_path contains ":\\Windows\\System32\\" or action_process_image_path contains ":\\Windows\\SysWOW64\\") and action_process_image_path endswith "\\cmd.exe")))
