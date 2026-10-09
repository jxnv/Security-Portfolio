// Title: Renamed Visual Studio Code Tunnel Execution
// ID: 2cf29f11-e356-4f61-98c0-1bdb9393d6da
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-28
// Tags: attack.command-and-control, attack.t1071.001, attack.t1219
// Description: Detects renamed Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_name = null and action_process_image_command_line endswith ".exe tunnel") or ((action_process_image_command_line contains ".exe tunnel" and action_process_image_command_line contains "--accept-server-license-terms")) or ((action_process_image_command_line contains "tunnel " and action_process_image_command_line contains "service" and action_process_image_command_line contains "internal-run" and action_process_image_command_line contains "tunnel-service.log"))) and not (((action_process_image_path endswith "\\code-tunnel.exe" or action_process_image_path endswith "\\code.exe")))) or ((actor_process_command_line endswith " tunnel" and action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "/d /c " and action_process_image_command_line contains "\\servers\\Stable-" and action_process_image_command_line contains "code-server.cmd")) and not (((actor_process_image_path endswith "\\code-tunnel.exe" or actor_process_image_path endswith "\\code.exe")))))
