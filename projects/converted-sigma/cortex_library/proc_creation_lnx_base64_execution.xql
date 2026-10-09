// Title: Linux Base64 Encoded Pipe to Shell
// ID: ba592c6d-6888-43c3-b8c6-689b8fe47337
// Status: test
// Level: medium
// Author: pH-T (Nextron Systems)
// Date: 2022-07-26
// Tags: attack.stealth, attack.t1140
// Description: Detects suspicious process command line that uses base64 encoded input for execution with a shell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "base64 ") and (((action_process_image_command_line contains "| bash " or action_process_image_command_line contains "| sh " or action_process_image_command_line contains "|bash " or action_process_image_command_line contains "|sh ")) or ((action_process_image_command_line endswith " |sh" or action_process_image_command_line endswith "| bash" or action_process_image_command_line endswith "| sh" or action_process_image_command_line endswith "|bash"))))
