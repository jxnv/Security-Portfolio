// Title: Visual Studio Code Tunnel Execution
// ID: 90d6bd71-dffb-4989-8d86-a827fedd6624
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), citron_ninja
// Date: 2023-10-25
// Tags: attack.command-and-control, attack.t1071.001, attack.t1219
// Description: Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = null and action_process_image_command_line endswith ".exe tunnel") or (actor_process_command_line endswith " tunnel" and action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "/d /c " and action_process_image_command_line contains "\\servers\\Stable-" and action_process_image_command_line contains "code-server.cmd")) or ((action_process_image_command_line contains ".exe tunnel" and action_process_image_command_line contains "--accept-server-license-terms")))
