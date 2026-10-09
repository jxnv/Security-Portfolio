// Title: Suspicious Mshta.EXE Execution Patterns
// ID: e32f92d1-523e-49c3-9374-bdb13b46a3ba
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-07-17
// Tags: attack.execution, attack.t1106
// Description: Detects suspicious mshta process execution patterns
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\mshta.exe") or (action_process_image_name = "MSHTA.EXE")) and ((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\wscript.exe") and (action_process_image_command_line contains "\\AppData\\Local\\" or action_process_image_command_line contains "C:\\ProgramData\\" or action_process_image_command_line contains "C:\\Users\\Public\\" or action_process_image_command_line contains "C:\\Windows\\Temp\\"))) or (((action_process_image_path endswith "\\mshta.exe") or (action_process_image_name = "MSHTA.EXE")) and not ((((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")) or ((action_process_image_command_line contains ".htm" or action_process_image_command_line contains ".hta")) or ((action_process_image_command_line endswith "mshta.exe" or action_process_image_command_line endswith "mshta"))))))
