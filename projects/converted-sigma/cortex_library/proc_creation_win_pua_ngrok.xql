// Title: PUA - Ngrok Execution
// ID: ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-05-14
// Tags: attack.command-and-control, attack.t1572
// Description: Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
// Involved domains are bin.equinox.io for download and *.ngrok.io for connections.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " tcp 139" or action_process_image_command_line contains " tcp 445" or action_process_image_command_line contains " tcp 3389" or action_process_image_command_line contains " tcp 5985" or action_process_image_command_line contains " tcp 5986")) or ((action_process_image_command_line contains " start " and action_process_image_command_line contains "--all" and action_process_image_command_line contains "--config" and action_process_image_command_line contains ".yml")) or (action_process_image_path endswith "ngrok.exe" and (action_process_image_command_line contains " tcp " or action_process_image_command_line contains " http " or action_process_image_command_line contains " authtoken ")) or ((action_process_image_command_line contains ".exe authtoken " or action_process_image_command_line contains ".exe start --all")))
