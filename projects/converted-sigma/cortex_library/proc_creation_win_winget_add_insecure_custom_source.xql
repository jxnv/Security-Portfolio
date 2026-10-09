// Title: Add Insecure Download Source To Winget
// ID: 81a0ecb5-0a41-4ba1-b2ba-c944eb92bfa2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.execution, attack.t1059
// Description: Detects usage of winget to add a new insecure (http) download source.
// Winget will not allow the addition of insecure sources, hence this could indicate potential suspicious activity (or typos)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "source " and action_process_image_command_line contains "add " and action_process_image_command_line contains "http://")) and ((action_process_image_path endswith "\\winget.exe") or (action_process_image_name = "winget.exe")))
