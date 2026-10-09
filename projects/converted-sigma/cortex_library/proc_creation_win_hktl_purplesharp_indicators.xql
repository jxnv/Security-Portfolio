// Title: HackTool - PurpleSharp Execution
// ID: ff23ffbc-3378-435e-992f-0624dcf93ab4
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2021-06-18
// Tags: attack.t1587, attack.resource-development
// Description: Detects the execution of the PurpleSharp adversary simulation tool
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "xyz123456.exe" or action_process_image_command_line contains "PurpleSharp")) or ((action_process_image_path contains "\\purplesharp") or (action_process_image_name = "PurpleSharp.exe")))
