// Title: Execution of Powershell Script in Public Folder
// ID: fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems)
// Date: 2022-04-06
// Tags: attack.execution, attack.t1059.001
// Description: This rule detects execution of PowerShell scripts located in the "C:\Users\Public" folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "-f C:\\Users\\Public" or action_process_image_command_line contains "-f \"C:\\Users\\Public" or action_process_image_command_line contains "-f %Public%" or action_process_image_command_line contains "-fi C:\\Users\\Public" or action_process_image_command_line contains "-fi \"C:\\Users\\Public" or action_process_image_command_line contains "-fi %Public%" or action_process_image_command_line contains "-fil C:\\Users\\Public" or action_process_image_command_line contains "-fil \"C:\\Users\\Public" or action_process_image_command_line contains "-fil %Public%" or action_process_image_command_line contains "-file C:\\Users\\Public" or action_process_image_command_line contains "-file \"C:\\Users\\Public" or action_process_image_command_line contains "-file %Public%"))
