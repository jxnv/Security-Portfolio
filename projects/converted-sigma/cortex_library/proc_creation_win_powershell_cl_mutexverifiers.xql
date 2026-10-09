// Title: Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
// ID: 1e0e1a81-e79b-44bc-935b-ddb9c8006b3d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113
// Date: 2022-05-21
// Tags: attack.stealth, attack.t1216
// Description: Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and action_process_image_path endswith "\\powershell.exe" and action_process_image_command_line contains " -nologo -windowstyle minimized -file ") and ((action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\Windows\\Temp\\")))
