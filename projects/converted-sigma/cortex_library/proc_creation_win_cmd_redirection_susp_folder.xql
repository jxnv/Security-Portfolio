// Title: Potentially Suspicious CMD Shell Output Redirect
// ID: 8e0bb260-d4b2-4fff-bb8d-3f82118e6892
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-12
// Tags: attack.stealth, attack.t1218
// Description: Detects inline Windows shell commands redirecting output via the ">" symbol to a suspicious location.
// This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as "hostname" and "dir" to files for future exfiltration.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")) and (((action_process_image_command_line contains ">?%APPDATA%\\" or action_process_image_command_line contains ">?%TEMP%\\" or action_process_image_command_line contains ">?%TMP%\\" or action_process_image_command_line contains ">?%USERPROFILE%\\" or action_process_image_command_line contains ">?C:\\ProgramData\\" or action_process_image_command_line contains ">?C:\\Temp\\" or action_process_image_command_line contains ">?C:\\Users\\Public\\" or action_process_image_command_line contains ">?C:\\Windows\\Temp\\")) or ((action_process_image_command_line contains " >" or action_process_image_command_line contains "\">" or action_process_image_command_line contains "'>") and (action_process_image_command_line contains "C:\\Users\\" and action_process_image_command_line contains "\\AppData\\Local\\"))))
