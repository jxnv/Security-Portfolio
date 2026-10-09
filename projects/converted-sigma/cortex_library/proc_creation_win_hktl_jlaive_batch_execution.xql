// Title: HackTool - Jlaive In-Memory Assembly Execution
// ID: 0a99eb3e-1617-41bd-b095-13dc767f3def
// Status: test
// Level: medium
// Author: Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)
// Date: 2022-05-24
// Tags: attack.execution, attack.t1059.003
// Description: Detects the use of Jlaive to execute assemblies in a copied PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\cmd.exe" and actor_process_command_line endswith ".bat") and ((action_process_image_path endswith "\\xcopy.exe" and (action_process_image_command_line contains "powershell.exe" and action_process_image_command_line contains ".bat.exe")) or (action_process_image_path endswith "\\xcopy.exe" and (action_process_image_command_line contains "pwsh.exe" and action_process_image_command_line contains ".bat.exe")) or (action_process_image_path endswith "\\attrib.exe" and (action_process_image_command_line contains "+s" and action_process_image_command_line contains "+h" and action_process_image_command_line contains ".bat.exe"))))
