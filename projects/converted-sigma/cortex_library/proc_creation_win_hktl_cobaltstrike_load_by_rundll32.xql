// Title: CobaltStrike Load by Rundll32
// ID: ae9c6a7c-9521-42a6-915e-5aaa8689d529
// Status: test
// Level: high
// Author: Wojciech Lesicki
// Date: 2021-06-01
// Tags: attack.stealth, attack.t1218.011
// Description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains ".dll" and (action_process_image_command_line endswith " StartW" or action_process_image_command_line endswith ",StartW")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE") or ((action_process_image_command_line contains "rundll32.exe" or action_process_image_command_line contains "rundll32 "))))
