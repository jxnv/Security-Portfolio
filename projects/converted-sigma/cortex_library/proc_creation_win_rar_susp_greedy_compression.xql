// Title: Suspicious Greedy Compression Using Rar.EXE
// ID: afe52666-401e-4a02-b4ff-5d128990b8cb
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2022-12-15
// Tags: attack.execution, attack.t1059
// Description: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rar.exe") or (Description = "Command line RAR")) or ((action_process_image_command_line contains ".exe a " or action_process_image_command_line contains " a -m"))) and (((action_process_image_command_line contains " -hp" and action_process_image_command_line contains " -r ")) and ((action_process_image_command_line contains " ?:\\\\\\*." or action_process_image_command_line contains " ?:\\\\\\\\\\*." or action_process_image_command_line contains " ?:\\$Recycle.bin\\" or action_process_image_command_line contains " ?:\\PerfLogs\\" or action_process_image_command_line contains " ?:\\Temp" or action_process_image_command_line contains " ?:\\Users\\Public\\" or action_process_image_command_line contains " ?:\\Windows\\" or action_process_image_command_line contains " %public%"))))
