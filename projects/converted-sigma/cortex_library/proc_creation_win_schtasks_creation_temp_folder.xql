// Title: Suspicious Scheduled Task Creation Involving Temp Folder
// ID: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-03-11
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\schtasks.exe" and (action_process_image_command_line contains " /create " and action_process_image_command_line contains " /sc once " and action_process_image_command_line contains "\\Temp\\"))
