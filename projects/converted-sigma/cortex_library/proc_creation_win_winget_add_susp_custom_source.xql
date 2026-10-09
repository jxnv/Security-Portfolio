// Title: Add Potential Suspicious New Download Source To Winget
// ID: c15a46a0-07d4-4c87-b4b6-89207835a83b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.execution, attack.t1059
// Description: Detects usage of winget to add new potentially suspicious download sources
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "source " and action_process_image_command_line contains "add ")) and ((action_process_image_path endswith "\\winget.exe") or (action_process_image_name = "winget.exe")) and (action_process_image_command_line ~= "://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"))
