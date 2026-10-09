// Title: Potential Arbitrary Code Execution Via Node.EXE
// ID: 6640f31c-01ad-49b5-beb5-83498a5cd8bd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects the execution node.exe which is shipped with multiple software such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\node.exe" and (action_process_image_command_line contains " -e " or action_process_image_command_line contains " --eval ")) and ((action_process_image_command_line contains ".exec(" and action_process_image_command_line contains "net.socket" and action_process_image_command_line contains ".connect" and action_process_image_command_line contains "child_process")))
