// Title: Cloudflared Tunnel Connections Cleanup
// ID: 7050bba1-1aed-454e-8f73-3f46f09ce56a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-17
// Tags: attack.command-and-control, attack.t1102, attack.t1090, attack.t1572
// Description: Detects execution of the "cloudflared" tool with the tunnel "cleanup" flag in order to cleanup tunnel connections.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " tunnel " and action_process_image_command_line contains "cleanup ") and (action_process_image_command_line contains "-config " or action_process_image_command_line contains "-connector-id "))
