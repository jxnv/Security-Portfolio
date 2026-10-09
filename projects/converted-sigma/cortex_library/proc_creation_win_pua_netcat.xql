// Title: PUA - Netcat Suspicious Execution
// ID: e31033fc-33f0-4020-9a16-faf9b31cbf08
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2021-07-21
// Tags: attack.command-and-control, attack.t1095
// Description: Detects execution of Netcat. Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -lvp " or action_process_image_command_line contains " -lvnp" or action_process_image_command_line contains " -l -v -p " or action_process_image_command_line contains " -lv -p " or action_process_image_command_line contains " -l --proxy-type http " or action_process_image_command_line contains " -vnl --exec " or action_process_image_command_line contains " -vnl -e " or action_process_image_command_line contains " --lua-exec " or action_process_image_command_line contains " --sh-exec ")) or ((action_process_image_path endswith "\\nc.exe" or action_process_image_path endswith "\\ncat.exe" or action_process_image_path endswith "\\netcat.exe")))
