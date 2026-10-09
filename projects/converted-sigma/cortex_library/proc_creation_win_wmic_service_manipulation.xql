// Title: Service Started/Stopped Via Wmic.EXE
// ID: 0b7163dc-7eee-4960-af17-c0cd517f92da
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.execution, attack.t1047
// Description: Detects usage of wmic to start or stop a service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " service " and action_process_image_command_line contains " call ") and (action_process_image_command_line contains "stopservice" or action_process_image_command_line contains "startservice")) and ((action_process_image_name = "wmic.exe") or (action_process_image_path endswith "\\WMIC.exe")))
