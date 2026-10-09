// Title: WSL Child Process Anomaly
// ID: 2267fe65-0681-42ad-9a6d-46553d3f3480
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-23
// Tags: attack.execution, attack.stealth, attack.t1218, attack.t1202
// Description: Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\wsl.exe" or actor_process_image_path endswith "\\wslhost.exe")) and (((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains "\\AppData\\Local\\Temp\\" or action_process_image_path contains "C:\\Users\\Public\\" or action_process_image_path contains "C:\\Windows\\Temp\\" or action_process_image_path contains "C:\\Temp\\" or action_process_image_path contains "\\Downloads\\" or action_process_image_path contains "\\Desktop\\"))))
