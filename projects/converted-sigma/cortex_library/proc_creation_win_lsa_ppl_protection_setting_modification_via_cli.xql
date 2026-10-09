// Title: LSA PPL Protection Setting Modification via CommandLine
// ID: 8c0eca51-0f88-4db2-9183-fdfb10c703f9
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-03-22
// Tags: attack.defense-impairment, attack.t1689
// Description: Detects modification of LSA PPL protection settings via CommandLine.
// It may indicate an attempt to disable protection and enable credential dumping tools to access LSASS process memory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ControlSet" and action_process_image_command_line contains "\\Control\\Lsa") and (action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains " add ")) and (((action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "reg.exe" or action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "IsPplAutoEnabled" or action_process_image_command_line contains "RunAsPPL" or action_process_image_command_line contains "RunAsPPLBoot")))
