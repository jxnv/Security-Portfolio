// Title: Discovery of a System Time
// ID: b243b280-65fe-48df-ba07-6ddea7646427
// Status: test
// Level: low
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.discovery, attack.t1124
// Description: Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe") and action_process_image_command_line contains "time") or (action_process_image_path endswith "\\w32tm.exe" and action_process_image_command_line contains "tz"))
