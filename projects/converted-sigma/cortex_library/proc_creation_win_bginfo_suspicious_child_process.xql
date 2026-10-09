// Title: Suspicious Child Process Of BgInfo.EXE
// ID: 811f459f-9231-45d4-959a-0266c6311987
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-16
// Tags: attack.execution, attack.stealth, attack.t1059.005, attack.t1218, attack.t1202
// Description: Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains "\\AppData\\Local\\" or action_process_image_path contains "\\AppData\\Roaming\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains ":\\Windows\\Temp\\" or action_process_image_path contains ":\\PerfLogs\\"))) and ((actor_process_image_path endswith "\\bginfo.exe" or actor_process_image_path endswith "\\bginfo64.exe")))
