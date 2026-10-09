// Title: Password Provided In Command Line Of Net.EXE
// ID: d4498716-1d52-438f-8084-4a603157d131
// Status: test
// Level: medium
// Author: Tim Shelton (HAWK.IO)
// Date: 2021-12-09
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.lateral-movement, attack.stealth, attack.t1021.002, attack.t1078
// Description: Detects a when net.exe is called with a password in the command line
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " use " and action_process_image_command_line contains ":*\\\\" and action_process_image_command_line contains "/USER:* *")) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe")))) and not ((action_process_image_command_line endswith " ")))
