// Title: HackTool - Certipy Execution
// ID: 6938366d-8954-4ddc-baff-c830b3ba8fcd
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Sittikorn Sangrattanapitak
// Date: 2023-04-17
// Tags: attack.discovery, attack.credential-access, attack.t1649
// Description: Detects Certipy execution, a tool for Active Directory Certificate Services enumeration and abuse based on PE metadata characteristics and common command line arguments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\Certipy.exe") or (action_process_image_name = "Certipy.exe") or (Description contains "Certipy")) or (((action_process_image_command_line contains " account " or action_process_image_command_line contains " auth " or action_process_image_command_line contains " cert " or action_process_image_command_line contains " find " or action_process_image_command_line contains " forge " or action_process_image_command_line contains " ptt " or action_process_image_command_line contains " relay " or action_process_image_command_line contains " req " or action_process_image_command_line contains " shadow " or action_process_image_command_line contains " template ")) and ((action_process_image_command_line contains " -bloodhound" or action_process_image_command_line contains " -ca-pfx " or action_process_image_command_line contains " -dc-ip " or action_process_image_command_line contains " -kirbi" or action_process_image_command_line contains " -old-bloodhound" or action_process_image_command_line contains " -pfx " or action_process_image_command_line contains " -target" or action_process_image_command_line contains " -template" or action_process_image_command_line contains " -username " or action_process_image_command_line contains " -vulnerable" or action_process_image_command_line contains "auth -pfx" or action_process_image_command_line contains "shadow auto" or action_process_image_command_line contains "shadow list"))))
