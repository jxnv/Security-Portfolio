// Title: Windows Share Mount Via Net.EXE
// ID: f117933c-980c-4f78-b384-e3d838111165
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-02
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects when a share is mounted using the "net.exe" utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " use " or action_process_image_command_line contains " \\\\\\\\")) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
