// Title: Notepad Password Files Discovery
// ID: 3b4e950b-a3ea-44d3-877e-432071990709
// Status: experimental
// Level: low
// Author: The DFIR Report
// Date: 2025-02-21
// Tags: attack.discovery, attack.t1083
// Description: Detects the execution of Notepad to open a file that has the string "password" which may indicate unauthorized access to credentials or suspicious activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\explorer.exe" and action_process_image_path endswith "\\notepad.exe" and (action_process_image_command_line endswith "password*.txt" or action_process_image_command_line endswith "password*.csv" or action_process_image_command_line endswith "password*.doc" or action_process_image_command_line endswith "password*.xls"))
