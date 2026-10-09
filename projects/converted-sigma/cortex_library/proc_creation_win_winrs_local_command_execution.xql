// Title: Winrs Local Command Execution
// ID: bcfece3d-56fe-4545-9931-3b8e92927db1
// Status: experimental
// Level: high
// Author: Liran Ravich, Nasreddine Bencherchali
// Date: 2025-10-22
// Tags: attack.lateral-movement, attack.stealth, attack.t1021.006, attack.t1218
// Description: Detects the execution of Winrs.exe where it is used to execute commands locally.
// Commands executed this way are launched under Winrshost.exe and can represent proxy execution used for defense evasion or lateral movement.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\winrs.exe") or (action_process_image_name = "winrs.exe")) and ((action_process_image_command_line contains "/r:localhost" or action_process_image_command_line contains "-r:localhost" or action_process_image_command_line contains "/r:127.0.0.1" or action_process_image_command_line contains "-r:127.0.0.1" or action_process_image_command_line contains "/r:[::1]" or action_process_image_command_line contains "-r:[::1]" or action_process_image_command_line contains "/remote:localhost" or action_process_image_command_line contains "-remote:localhost" or action_process_image_command_line contains "/remote:127.0.0.1" or action_process_image_command_line contains "-remote:127.0.0.1" or action_process_image_command_line contains "/remote:[::1]" or action_process_image_command_line contains "-remote:[::1]"))) or (((action_process_image_path endswith "\\winrs.exe") or (action_process_image_name = "winrs.exe")) and not (((action_process_image_command_line contains "/r:" or action_process_image_command_line contains "-r:" or action_process_image_command_line contains "/remote:" or action_process_image_command_line contains "-remote:")))))
