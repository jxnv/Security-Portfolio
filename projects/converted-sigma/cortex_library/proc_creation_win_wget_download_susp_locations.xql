// Title: Suspicious File Download From IP Via Wget.EXE - Paths
// ID: 40aa399c-7b02-4715-8e5f-73572b493f33
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-23
// Tags: attack.execution
// Description: Detects potentially suspicious file downloads directly from IP addresses and stored in suspicious locations using Wget.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line ~= "\\s-O\\s") or (action_process_image_command_line contains "--output-document")) and (action_process_image_command_line contains "http") and ((action_process_image_path endswith "\\wget.exe") or (action_process_image_name = "wget.exe")) and (action_process_image_command_line ~= "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") and (((action_process_image_command_line contains ":\\PerfLogs\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Help\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\Temporary Internet")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Favorites\\")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Favourites\\")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Contacts\\")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Pictures\\"))))
