// Title: Suspicious Provlaunch.EXE Child Process
// ID: f9999590-1f94-4a34-a91e-951e47bedefd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-08
// Tags: attack.stealth, attack.t1218
// Description: Detects suspicious child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains ":\\PerfLogs\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains "\\AppData\\Temp\\" or action_process_image_path contains "\\Windows\\System32\\Tasks\\" or action_process_image_path contains "\\Windows\\Tasks\\" or action_process_image_path contains "\\Windows\\Temp\\"))) and (actor_process_image_path endswith "\\provlaunch.exe"))
