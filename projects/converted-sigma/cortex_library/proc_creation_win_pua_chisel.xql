// Title: PUA - Chisel Tunneling Tool Execution
// ID: 8b0e12da-d3c3-49db-bb4f-256703f380e5
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-13
// Tags: attack.command-and-control, attack.t1090.001
// Description: Detects usage of the Chisel tunneling tool via the commandline arguments
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\chisel.exe") or (((action_process_image_command_line contains "exe client " or action_process_image_command_line contains "exe server ")) and ((action_process_image_command_line contains "-socks5" or action_process_image_command_line contains "-reverse" or action_process_image_command_line contains " r:" or action_process_image_command_line contains ":127.0.0.1:" or action_process_image_command_line contains "-tls-skip-verify " or action_process_image_command_line contains ":socks"))))
