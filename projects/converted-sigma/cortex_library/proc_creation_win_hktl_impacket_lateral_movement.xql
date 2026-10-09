// Title: HackTool - Potential Impacket Lateral Movement Activity
// ID: 10c14723-61c7-4c75-92ca-9af245723ad2
// Status: stable
// Level: high
// Author: Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch
// Date: 2019-09-03
// Tags: attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.003
// Description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line contains "svchost.exe -k netsvcs" or actor_process_command_line contains "taskeng.exe") and (action_process_image_command_line contains "cmd.exe" and action_process_image_command_line contains "/C" and action_process_image_command_line contains "Windows\\Temp\\" and action_process_image_command_line contains "&1")) or ((actor_process_image_path endswith "\\wmiprvse.exe" or actor_process_image_path endswith "\\mmc.exe" or actor_process_image_path endswith "\\explorer.exe" or actor_process_image_path endswith "\\services.exe") and (action_process_image_command_line contains "cmd.exe" and action_process_image_command_line contains "/Q" and action_process_image_command_line contains "/c" and action_process_image_command_line contains "\\\\\\\\127.0.0.1\\\\" and action_process_image_command_line contains "&1")))
