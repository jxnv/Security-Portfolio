// Title: New User Created Via Net.EXE With Never Expire Option
// ID: b9f0e6f5-09b4-4358-bae4-08408705bd5c
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-12
// Tags: attack.persistence, attack.t1136.001
// Description: Detects creation of local users via the net.exe command with the option "never expire"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "user" and action_process_image_command_line contains "add" and action_process_image_command_line contains "expires:never")) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
