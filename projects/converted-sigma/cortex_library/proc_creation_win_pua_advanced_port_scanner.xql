// Title: PUA - Advanced Port Scanner Execution
// ID: 54773c5f-f1cc-4703-9126-2f797d96a69d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-18
// Tags: attack.discovery, attack.t1046, attack.t1135
// Description: Detects the use of Advanced Port Scanner.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/portable" and action_process_image_command_line contains "/lng")) or ((action_process_image_path contains "\\advanced_port_scanner") or (action_process_image_name contains "advanced_port_scanner") or (Description contains "Advanced Port Scanner")))
