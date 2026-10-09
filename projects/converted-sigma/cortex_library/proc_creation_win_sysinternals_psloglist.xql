// Title: Suspicious Use of PsLogList
// ID: aae1243f-d8af-40d8-ab20-33fc6d0c55bc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-18
// Tags: attack.discovery, attack.t1087, attack.t1087.001, attack.t1087.002
// Description: Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery or delete events logs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " security" or action_process_image_command_line contains " application" or action_process_image_command_line contains " system")) and ((action_process_image_command_line contains " -d" or action_process_image_command_line contains " -x" or action_process_image_command_line contains " -s" or action_process_image_command_line contains " -c" or action_process_image_command_line contains " -g")) and ((action_process_image_name = "psloglist.exe") or ((action_process_image_path endswith "\\psloglist.exe" or action_process_image_path endswith "\\psloglist64.exe" or action_process_image_path endswith "\\psloglist64a.exe"))))
