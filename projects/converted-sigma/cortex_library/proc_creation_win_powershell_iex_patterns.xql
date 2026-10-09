// Title: Suspicious PowerShell IEX Execution Patterns
// ID: 09576804-7a05-458e-a817-eb718ca91f54
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-03-24
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious ways to run Invoke-Execution using IEX alias
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains " | iex;" or action_process_image_command_line contains " | iex " or action_process_image_command_line contains " | iex}" or action_process_image_command_line contains " | IEX ;" or action_process_image_command_line contains " | IEX -Error" or action_process_image_command_line contains " | IEX (new" or action_process_image_command_line contains ");IEX ")) and ((action_process_image_command_line contains "::FromBase64String" or action_process_image_command_line contains ".GetString([System.Convert]::"))) or ((action_process_image_command_line contains ")|iex;$" or action_process_image_command_line contains ");iex($" or action_process_image_command_line contains ");iex $" or action_process_image_command_line contains " | IEX | " or action_process_image_command_line contains " | iex\\\"")))
