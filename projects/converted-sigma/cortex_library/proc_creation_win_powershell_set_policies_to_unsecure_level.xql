// Title: Change PowerShell Policies to an Insecure Level
// ID: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-11-01
// Tags: attack.execution, attack.t1059.001
// Description: Detects changing the PowerShell script execution policy to a potentially insecure level using the "-ExecutionPolicy" flag.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_name = "powershell_ise.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or ((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))) and ((action_process_image_command_line contains "Bypass" or action_process_image_command_line contains "Unrestricted")) and ((action_process_image_command_line contains "-executionpolicy " or action_process_image_command_line contains " -ep " or action_process_image_command_line contains " -exec "))) and not (((actor_process_image_path = "C:\\Windows\\SysWOW64\\msiexec.exe" or actor_process_image_path = "C:\\Windows\\System32\\msiexec.exe") and (action_process_image_command_line contains "-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files\\PowerShell\\7\\" or action_process_image_command_line contains "-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files (x86)\\PowerShell\\7\\"))) and not (((actor_process_image_path contains "C:\\Program Files\\Avast Software\\Avast\\" or actor_process_image_path contains "C:\\Program Files (x86)\\Avast Software\\Avast\\" or actor_process_image_path contains "\\instup.exe") and (action_process_image_command_line contains "-ExecutionPolicy ByPass -File \"C:\\Program Files\\Avast Software\\Avast" or action_process_image_command_line contains "-ExecutionPolicy ByPass -File \"C:\\Program Files (x86)\\Avast Software\\Avast\\"))))
