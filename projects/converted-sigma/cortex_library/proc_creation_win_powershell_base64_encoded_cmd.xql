// Title: Suspicious Encoded PowerShell Command Line
// ID: ca2092a1-c273-4878-9b4b-0d60115bf5ea
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community
// Date: 2018-09-03
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((((action_process_image_command_line contains " JAB" or action_process_image_command_line contains " SUVYI" or action_process_image_command_line contains " SQBFAFgA" or action_process_image_command_line contains " aQBlAHgA" or action_process_image_command_line contains " aWV4I" or action_process_image_command_line contains " IAA" or action_process_image_command_line contains " IAB" or action_process_image_command_line contains " UwB" or action_process_image_command_line contains " cwB")) and (action_process_image_command_line contains " -e")) or ((action_process_image_command_line contains ".exe -ENCOD " or action_process_image_command_line contains " BA^J e-"))) and not ((action_process_image_command_line contains " -ExecutionPolicy remotesigned ")))
