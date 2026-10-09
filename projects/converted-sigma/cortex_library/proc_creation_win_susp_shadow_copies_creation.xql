// Title: Shadow Copies Creation Using Operating Systems Utilities
// ID: b17ea6f7-6e90-447e-a799-e6c0a493d6ce
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003, attack.t1003.002, attack.t1003.003
// Description: Shadow Copies creation using operating systems utilities, possible credential access
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "shadow" and action_process_image_command_line contains "create")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\vssadmin.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "wmic.exe" or action_process_image_name = "VSSADMIN.EXE"))))
