// Title: New Network Trace Capture Started Via Netsh.EXE
// ID: d3c3861d-c504-4c77-ba55-224ba82d0118
// Status: test
// Level: medium
// Author: Kutepov Anton, oscd.community
// Date: 2019-10-24
// Tags: attack.discovery, attack.credential-access, attack.t1040
// Description: Detects the execution of netsh with the "trace" flag in order to start a network capture
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "trace" and action_process_image_command_line contains "start")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
