// Title: Interactive AT Job
// ID: 60fc936d-2eb0-4543-8a13-911c750a1dfc
// Status: test
// Level: high
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.t1053.002
// Description: Detects an interactive AT job, which may be used as a form of privilege escalation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\at.exe" and action_process_image_command_line contains "interactive")
