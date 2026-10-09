// Title: Suspicious DumpMinitool Execution
// ID: eb1c4225-1c23-4241-8dd4-051389fde4ce
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-06
// Tags: attack.credential-access, attack.stealth, attack.t1036, attack.t1003.001
// Description: Detects suspicious ways to use the "DumpMinitool.exe" binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\DumpMinitool.exe" or action_process_image_path endswith "\\DumpMinitool.x86.exe" or action_process_image_path endswith "\\DumpMinitool.arm64.exe")) or ((action_process_image_name = "DumpMinitool.exe" or action_process_image_name = "DumpMinitool.x86.exe" or action_process_image_name = "DumpMinitool.arm64.exe"))) and (not (((action_process_image_path contains "\\Microsoft Visual Studio\\" or action_process_image_path contains "\\Extensions\\"))) or (action_process_image_command_line contains ".txt") or (((action_process_image_command_line contains " Full" or action_process_image_command_line contains " Mini" or action_process_image_command_line contains " WithHeap")) and not ((action_process_image_command_line contains "--dumpType")))))
