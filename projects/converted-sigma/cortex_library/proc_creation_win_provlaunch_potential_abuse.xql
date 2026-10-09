// Title: Potential Provlaunch.EXE Binary Proxy Execution Abuse
// ID: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
// Date: 2023-08-08
// Tags: attack.stealth, attack.t1218
// Description: Detects child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\provlaunch.exe") and not ((((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains ":\\PerfLogs\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains "\\AppData\\Temp\\" or action_process_image_path contains "\\Windows\\System32\\Tasks\\" or action_process_image_path contains "\\Windows\\Tasks\\" or action_process_image_path contains "\\Windows\\Temp\\")))))
