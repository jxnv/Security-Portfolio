// Title: Add New Download Source To Winget
// ID: 05ebafc8-7aa2-4bcd-a269-2aec93f9e842
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.execution, attack.t1059
// Description: Detects usage of winget to add new additional download sources
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "source " and action_process_image_command_line contains "add ")) and ((action_process_image_path endswith "\\winget.exe") or (action_process_image_name = "winget.exe")))
