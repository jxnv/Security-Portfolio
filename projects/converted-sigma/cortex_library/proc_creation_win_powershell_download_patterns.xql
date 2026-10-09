// Title: PowerShell Download Pattern
// ID: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
// Date: 2019-01-16
// Tags: attack.execution, attack.t1059.001
// Description: Detects a Powershell process that contains download commands in its command line string
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "new-object" and action_process_image_command_line contains "net.webclient)." and action_process_image_command_line contains "download") and (action_process_image_command_line contains "string(" or action_process_image_command_line contains "file(")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell_ISE.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
