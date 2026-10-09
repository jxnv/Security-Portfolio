// Title: Exports Critical Registry Keys To a File
// ID: 82880171-b475-4201-b811-e9c826cd5eaa
// Status: test
// Level: high
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-12
// Tags: attack.exfiltration, attack.discovery, attack.t1012
// Description: Detects the export of a crital Registry key to a file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -E ") and ((action_process_image_command_line contains "hklm" or action_process_image_command_line contains "hkey_local_machine")) and ((action_process_image_command_line endswith "\\system" or action_process_image_command_line endswith "\\sam" or action_process_image_command_line endswith "\\security")) and ((action_process_image_path endswith "\\regedit.exe") or (action_process_image_name = "REGEDIT.EXE")))
