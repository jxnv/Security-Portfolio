// Title: Filter Driver Unloaded Via Fltmc.EXE
// ID: 4931188c-178e-4ee7-a348-39e8a7a56821
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-13
// Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, attack.t1685.001
// Description: Detect filter driver unloading activity via fltmc.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "unload") and ((action_process_image_path endswith "\\fltMC.exe") or (action_process_image_name = "fltMC.exe"))) and not ((((actor_process_image_path contains "\\AppData\\Local\\Temp\\" or actor_process_image_path contains ":\\Windows\\Temp\\") and actor_process_image_path endswith "\\endpoint-protection-installer-x64.tmp" and (action_process_image_command_line endswith "unload rtp_filesystem_filter" or action_process_image_command_line endswith "unload rtp_filter")) or (actor_process_image_path = "C:\\Program Files (x86)\\ManageEngine\\uems_agent\\bin\\dcfaservice64.exe" and action_process_image_command_line endswith "unload DFMFilter"))))
