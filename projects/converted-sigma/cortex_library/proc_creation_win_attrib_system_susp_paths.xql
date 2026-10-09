// Title: Set Suspicious Files as System Files Using Attrib.EXE
// ID: efec536f-72e8-4656-8960-5e85d091345b
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-28
// Tags: attack.stealth, attack.t1564.001
// Description: Detects the usage of attrib with the "+s" option to set scripts or executables located in suspicious locations as system files to hide them from users and make them unable to be deleted with simple rights. The rule limits the search to specific extensions and directories to avoid FPs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " +s") and ((action_process_image_command_line contains ".bat" or action_process_image_command_line contains ".dll" or action_process_image_command_line contains ".exe" or action_process_image_command_line contains ".hta" or action_process_image_command_line contains ".ps1" or action_process_image_command_line contains ".vbe" or action_process_image_command_line contains ".vbs")) and ((action_process_image_path endswith "\\attrib.exe") or (action_process_image_name = "ATTRIB.EXE")) and ((action_process_image_command_line contains " %" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\AppData\\Local\\" or action_process_image_command_line contains "\\ProgramData\\" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Windows\\Temp\\"))) and not (((action_process_image_command_line contains "\\Windows\\TEMP\\" and action_process_image_command_line contains ".exe"))))
