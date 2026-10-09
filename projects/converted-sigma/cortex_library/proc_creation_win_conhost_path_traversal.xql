// Title: Conhost.exe CommandLine Path Traversal
// ID: ee5e119b-1f75-4b34-add8-3be976961e39
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-14
// Tags: attack.execution, attack.t1059.003
// Description: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_command_line contains "conhost" and action_process_image_command_line contains "/../../")
