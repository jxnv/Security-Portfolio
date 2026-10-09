// Title: Rundll32 UNC Path Execution
// ID: 5cdb711b-5740-4fb2-ba88-f7945027afac
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-10
// Tags: attack.execution, attack.lateral-movement, attack.stealth, attack.t1021.002, attack.t1218.011
// Description: Detects rundll32 execution where the DLL is located on a remote location (share).
// Threat actors can abuse the rundll32.exe binary to execute remote DLLs from a UNC pathh.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " \\\\\\\\" or action_process_image_command_line contains " '\\\\\\\\" or action_process_image_command_line contains " \"\\\\\\\\")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE") or (action_process_image_command_line contains "rundll32"))) and not ((action_process_image_command_line contains "\\\\\\\\.\\\\pipe")))
