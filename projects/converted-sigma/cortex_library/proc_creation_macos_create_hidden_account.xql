// Title: Hidden User Creation
// ID: b22a5b36-2431-493a-8be1-0bae56c28ef3
// Status: test
// Level: medium
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-10
// Tags: attack.stealth, attack.t1564.002
// Description: Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/dscl" and action_process_image_command_line contains "create") and (action_process_image_command_line contains "UniqueID" and action_process_image_command_line ~= "([0-9]|[1-9][0-9]|[1-4][0-9]{2})")) or ((action_process_image_path endswith "/dscl" and action_process_image_command_line contains "create") and ((action_process_image_command_line contains "IsHidden") and ((action_process_image_command_line contains "true" or action_process_image_command_line contains "yes" or action_process_image_command_line contains "1")))))
