// Title: Suspicious XOR Encoded PowerShell Command
// ID: bb780e0c-16cf-4383-8383-1e5471db6cf9
// Status: test
// Level: medium
// Author: Sami Ruohonen, Harish Segar, Tim Shelton, Teymur Kheirkhabarov, Vasiliy Burov, oscd.community, Nasreddine Bencherchali
// Date: 2018-09-05
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1140, attack.t1027
// Description: Detects presence of a potentially xor encoded powershell command
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ForEach" or action_process_image_command_line contains "for(" or action_process_image_command_line contains "for " or action_process_image_command_line contains "-join " or action_process_image_command_line contains "-join'" or action_process_image_command_line contains "-join\"" or action_process_image_command_line contains "-join`" or action_process_image_command_line contains "::Join" or action_process_image_command_line contains "[char]")) and (action_process_image_command_line contains "bxor") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or (Description = "Windows PowerShell") or (Product = "PowerShell Core 6")))
