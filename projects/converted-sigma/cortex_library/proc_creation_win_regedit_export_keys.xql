// Title: Exports Registry Key To a File
// ID: f0e53e89-8d22-46ea-9db5-9d4796ee2f8a
// Status: test
// Level: low
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-07
// Tags: attack.exfiltration, attack.discovery, attack.t1012
// Description: Detects the export of the target Registry key to a file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -E ") and ((action_process_image_path endswith "\\regedit.exe") or (action_process_image_name = "REGEDIT.EXE"))) and not ((((action_process_image_command_line contains "hklm" or action_process_image_command_line contains "hkey_local_machine")) and ((action_process_image_command_line endswith "\\system" or action_process_image_command_line endswith "\\sam" or action_process_image_command_line endswith "\\security")))))
