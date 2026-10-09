// Title: Regsvr32 Execution From Potential Suspicious Location
// ID: 9525dc73-0327-438c-8c04-13c0e037e9da
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-26
// Tags: attack.stealth, attack.t1218.010
// Description: Detects execution of regsvr32 where the DLL is located in a potentially suspicious location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ":\\ProgramData\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\AppData\\Roaming\\")) and ((action_process_image_path endswith "\\regsvr32.exe") or (action_process_image_name = "REGSVR32.EXE")))
