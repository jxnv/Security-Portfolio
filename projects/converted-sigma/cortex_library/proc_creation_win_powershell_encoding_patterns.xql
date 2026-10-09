// Title: Potential Encoded PowerShell Patterns In CommandLine
// ID: cdf05894-89e7-4ead-b2b0-0a5f97a90f2f
// Status: test
// Level: low
// Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
// Date: 2020-10-11
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects specific combinations of encoding methods in PowerShell via the commandline
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((((action_process_image_command_line contains "ToInt" or action_process_image_command_line contains "ToDecimal" or action_process_image_command_line contains "ToByte" or action_process_image_command_line contains "ToUint" or action_process_image_command_line contains "ToSingle" or action_process_image_command_line contains "ToSByte")) and ((action_process_image_command_line contains "ToChar" or action_process_image_command_line contains "ToString" or action_process_image_command_line contains "String"))) or (((action_process_image_command_line contains "char" and action_process_image_command_line contains "join")) or ((action_process_image_command_line contains "split" and action_process_image_command_line contains "join")))))
