// Title: Suspicious Scheduled Task Write to System32 Tasks
// ID: 80e1f67a-4596-4351-98f5-a9c3efabac95
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-11-16
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053
// Description: Detects the creation of tasks from processes executed from suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path contains "\\Windows\\System32\\Tasks" and (action_process_image_path contains "\\AppData\\" or action_process_image_path contains "C:\\PerfLogs" or action_process_image_path contains "\\Windows\\System32\\config\\systemprofile"))
