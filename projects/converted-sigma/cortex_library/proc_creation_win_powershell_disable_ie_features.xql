// Title: Disabled IE Security Features
// ID: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-06-19
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -name IEHarden " and action_process_image_command_line contains " -value 0 ")) or ((action_process_image_command_line contains " -name DEPOff " and action_process_image_command_line contains " -value 1 ")) or ((action_process_image_command_line contains " -name DisableFirstRunCustomize " and action_process_image_command_line contains " -value 2 ")))
