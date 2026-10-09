// Title: PowerShell SAM Copy
// ID: 1af57a4b-460a-4738-9034-db68b880c665
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-29
// Tags: attack.credential-access, attack.t1003.002
// Description: Detects suspicious PowerShell scripts accessing SAM hives
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\HarddiskVolumeShadowCopy" and action_process_image_command_line contains "System32\\config\\sam")) and ((action_process_image_command_line contains "Copy-Item" or action_process_image_command_line contains "cp $_." or action_process_image_command_line contains "cpi $_." or action_process_image_command_line contains "copy $_." or action_process_image_command_line contains ".File]::Copy(")))
