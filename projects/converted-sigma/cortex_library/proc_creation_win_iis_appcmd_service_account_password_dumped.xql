// Title: Microsoft IIS Service Account Password Dumped
// ID: 2d3cdeec-c0db-45b4-aa86-082f7eb75701
// Status: test
// Level: high
// Author: Tim Rauch, Janantha Marasinghe, Elastic (original idea)
// Date: 2022-11-08
// Tags: attack.credential-access, attack.t1003
// Description: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "list ") and ((action_process_image_path endswith "\\appcmd.exe") or (action_process_image_name = "appcmd.exe"))) and (((action_process_image_command_line contains " /config" or action_process_image_command_line contains " /xml" or action_process_image_command_line contains " -config" or action_process_image_command_line contains " -xml")) or (((action_process_image_command_line contains " /@t" or action_process_image_command_line contains " /text" or action_process_image_command_line contains " /show" or action_process_image_command_line contains " -@t" or action_process_image_command_line contains " -text" or action_process_image_command_line contains " -show")) and ((action_process_image_command_line contains ":\\*" or action_process_image_command_line contains "password")))))
