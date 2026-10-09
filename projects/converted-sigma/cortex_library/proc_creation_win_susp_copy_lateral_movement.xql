// Title: Copy From Or To Admin Share Or Sysvol Folder
// ID: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali
// Date: 2019-12-30
// Tags: attack.lateral-movement, attack.collection, attack.exfiltration, attack.t1039, attack.t1048, attack.t1021.002
// Description: Detects a copy command or a copy utility execution to or from an Admin share or remote
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\\\\\\\*\\\\*$" or action_process_image_command_line contains "\\Sysvol\\")) and ((((action_process_image_path endswith "\\robocopy.exe" or action_process_image_path endswith "\\xcopy.exe")) or ((action_process_image_name = "robocopy.exe" or action_process_image_name = "XCOPY.EXE"))) or ((action_process_image_command_line contains "copy") and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe"))) or (((action_process_image_command_line contains "copy-item" or action_process_image_command_line contains "copy " or action_process_image_command_line contains "cpi " or action_process_image_command_line contains " cp " or action_process_image_command_line contains "move " or action_process_image_command_line contains " move-item" or action_process_image_command_line contains " mi " or action_process_image_command_line contains " mv ")) and (((action_process_image_path contains "\\powershell_ise.exe" or action_process_image_path contains "\\powershell.exe" or action_process_image_path contains "\\pwsh.exe")) or ((action_process_image_name = "powershell_ise.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))))
