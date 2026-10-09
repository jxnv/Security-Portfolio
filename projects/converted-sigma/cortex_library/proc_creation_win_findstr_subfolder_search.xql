// Title: Insensitive Subfolder Search Via Findstr.EXE
// ID: 04936b66-3915-43ad-a8e5-809eadfd1141
// Status: test
// Level: low
// Author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-10-05
// Tags: attack.credential-access, attack.command-and-control, attack.stealth, attack.t1218, attack.t1564.004, attack.t1552.001, attack.t1105
// Description: Detects execution of findstr with the "s" and "i" flags for a "subfolder" and "insensitive" search respectively. Attackers sometimes leverage this built-in utility to search the system for interesting files or filter through results of commands.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "findstr") or (action_process_image_path endswith "findstr.exe") or (action_process_image_name = "FINDSTR.EXE")) and ((action_process_image_command_line contains " -i ") and (action_process_image_command_line contains " -s ")))
