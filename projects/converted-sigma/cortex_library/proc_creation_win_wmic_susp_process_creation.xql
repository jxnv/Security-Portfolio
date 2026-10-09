// Title: Suspicious Process Created Via Wmic.EXE
// ID: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-10-12
// Tags: attack.execution, attack.t1047
// Description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "process " and action_process_image_command_line contains "call " and action_process_image_command_line contains "create ") and (action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "bitsadmin" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "cmd.exe /c " or action_process_image_command_line contains "cmd.exe /k " or action_process_image_command_line contains "cmd.exe /r " or action_process_image_command_line contains "cmd /c " or action_process_image_command_line contains "cmd /k " or action_process_image_command_line contains "cmd /r " or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "pwsh" or action_process_image_command_line contains "certutil" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\" or action_process_image_command_line contains "%temp%" or action_process_image_command_line contains "%tmp%" or action_process_image_command_line contains "%ProgramData%" or action_process_image_command_line contains "%appdata%" or action_process_image_command_line contains "%comspec%" or action_process_image_command_line contains "%localappdata%"))
