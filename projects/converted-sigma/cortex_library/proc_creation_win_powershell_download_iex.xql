// Title: PowerShell Download and Execution Cradles
// ID: 85b0b087-eddf-4a2b-b033-d771fa2b9775
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-24
// Tags: attack.execution, attack.t1059
// Description: Detects PowerShell download and execution cradles.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".DownloadString(" or action_process_image_command_line contains ".DownloadFile(" or action_process_image_command_line contains "Invoke-WebRequest " or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "Invoke-RestMethod " or action_process_image_command_line contains "irm ")) and ((action_process_image_command_line contains ";iex $" or action_process_image_command_line contains "| IEX" or action_process_image_command_line contains "|IEX " or action_process_image_command_line contains "I`E`X" or action_process_image_command_line contains "I`EX" or action_process_image_command_line contains "IE`X" or action_process_image_command_line contains "iex " or action_process_image_command_line contains "IEX (" or action_process_image_command_line contains "IEX(" or action_process_image_command_line contains "Invoke-Expression")))
