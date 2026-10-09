// Title: Abusing Print Executable
// ID: bafac3d6-7de9-4dd9-8874-4a1194b493ed
// Status: test
// Level: medium
// Author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative
// Date: 2020-10-05
// Tags: attack.stealth, attack.t1218
// Description: Attackers can use print.exe for remote file copy
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\print.exe" and action_process_image_command_line startswith "print" and (action_process_image_command_line contains "/D" and action_process_image_command_line contains ".exe")) and not ((action_process_image_command_line contains "print.exe")))
