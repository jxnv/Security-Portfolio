// Title: Powershell Inline Execution From A File
// ID: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-12-25
// Tags: attack.execution, attack.t1059.001
// Description: Detects inline execution of PowerShell code from a file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "iex " or action_process_image_command_line contains "Invoke-Expression " or action_process_image_command_line contains "Invoke-Command " or action_process_image_command_line contains "icm ")) and (action_process_image_command_line contains " -raw") and ((action_process_image_command_line contains "cat " or action_process_image_command_line contains "get-content " or action_process_image_command_line contains "type ")))
