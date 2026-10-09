// Title: DumpMinitool Execution
// ID: dee0a7a3-f200-4112-a99b-952196d81e42
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2022-04-06
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects the use of "DumpMinitool.exe" a tool that allows the dump of process memory via the use of the "MiniDumpWriteDump"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " Full" or action_process_image_command_line contains " Mini" or action_process_image_command_line contains " WithHeap")) and (((action_process_image_path endswith "\\DumpMinitool.exe" or action_process_image_path endswith "\\DumpMinitool.x86.exe" or action_process_image_path endswith "\\DumpMinitool.arm64.exe")) or ((action_process_image_name = "DumpMinitool.exe" or action_process_image_name = "DumpMinitool.x86.exe" or action_process_image_name = "DumpMinitool.arm64.exe"))))
