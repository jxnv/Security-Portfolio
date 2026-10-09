// Title: TeamViewer Log File Deleted
// ID: b1decb61-ed83-4339-8e95-53ea51901720
// Status: test
// Level: low
// Author: frack113
// Date: 2022-01-16
// Tags: attack.stealth, attack.t1070.004
// Description: Detects the deletion of the TeamViewer log files which may indicate an attempt to destroy forensic evidence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\TeamViewer_" and action_file_path endswith ".log") and not ((action_process_image_path = "C:\\Windows\\system32\\svchost.exe")))
