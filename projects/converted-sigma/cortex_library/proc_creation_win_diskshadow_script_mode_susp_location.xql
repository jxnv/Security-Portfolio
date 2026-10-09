// Title: Diskshadow Script Mode - Execution From Potential Suspicious Location
// ID: fa1a7e52-3d02-435b-81b8-00da14dd66c1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-15
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of "Diskshadow.exe" in script mode using the "/s" flag where the script is located in a potentially suspicious location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-s " or action_process_image_command_line contains "/s ")) and ((action_process_image_name = "diskshadow.exe") or (action_process_image_path endswith "\\diskshadow.exe")) and ((action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\" or action_process_image_command_line contains "\\AppData\\Roaming\\" or action_process_image_command_line contains "\\ProgramData\\" or action_process_image_command_line contains "\\Users\\Public\\")))
