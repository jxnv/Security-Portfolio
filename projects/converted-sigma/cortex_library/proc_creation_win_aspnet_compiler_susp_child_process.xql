// Title: Suspicious Child Process of AspNetCompiler
// ID: 9ccba514-7cb6-4c5c-b377-700758f2f120
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-14
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects potentially suspicious child processes of "aspnet_compiler.exe".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\notepad.exe")) or ((action_process_image_path contains "\\Users\\Public\\" or action_process_image_path contains "\\AppData\\Local\\Temp\\" or action_process_image_path contains "\\AppData\\Local\\Roaming\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains ":\\Windows\\Temp\\" or action_process_image_path contains ":\\Windows\\System32\\Tasks\\" or action_process_image_path contains ":\\Windows\\Tasks\\"))) and (actor_process_image_path endswith "\\aspnet_compiler.exe"))
