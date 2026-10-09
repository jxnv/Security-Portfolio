// Title: Potential Privilege Escalation To LOCAL SYSTEM
// ID: 207b0396-3689-42d9-8399-4222658efc99
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-05-22
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects unknown program using commandline flags usually used by tools such as PsExec and PAExec to start programs with SYSTEM Privileges
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -s cmd" or action_process_image_command_line contains " -s -i cmd" or action_process_image_command_line contains " -i -s cmd" or action_process_image_command_line contains " -s pwsh" or action_process_image_command_line contains " -s -i pwsh" or action_process_image_command_line contains " -i -s pwsh" or action_process_image_command_line contains " -s powershell" or action_process_image_command_line contains " -s -i powershell" or action_process_image_command_line contains " -i -s powershell")) and not (((action_process_image_command_line contains "paexec" or action_process_image_command_line contains "PsExec" or action_process_image_command_line contains "accepteula"))))
