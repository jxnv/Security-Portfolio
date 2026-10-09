// Title: HackTool - KrbRelay Execution
// ID: e96253b8-6b3b-4f90-9e59-3b24b99cf9b4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-27
// Tags: attack.credential-access, attack.t1558.003
// Description: Detects the use of KrbRelay, a Kerberos relaying tool
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -spn " and action_process_image_command_line contains " -clsid " and action_process_image_command_line contains " -rbcd ")) or ((action_process_image_command_line contains "shadowcred" and action_process_image_command_line contains "clsid" and action_process_image_command_line contains "spn")) or ((action_process_image_command_line contains "spn " and action_process_image_command_line contains "session " and action_process_image_command_line contains "clsid ")) or ((action_process_image_path endswith "\\KrbRelay.exe") or (action_process_image_name = "KrbRelay.exe")))
