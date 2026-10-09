// Title: Remote Access Tool - AnyDesk Piped Password Via CLI
// ID: b1377339-fda6-477a-b455-ac0923f9ec2c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-28
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "/c " and action_process_image_command_line contains "echo " and action_process_image_command_line contains ".exe --set-password"))
