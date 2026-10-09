// Title: Execute Code with Pester.bat
// ID: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-08
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1216
// Description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "Pester" and action_process_image_command_line contains "Get-Help")) or ((action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "pester" and action_process_image_command_line contains ";")) and ((action_process_image_command_line contains "help" or action_process_image_command_line contains "\\?"))))
