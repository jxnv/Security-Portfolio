// Title: Java Running with Remote Debugging
// ID: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-01-16
// Tags: attack.t1203, attack.execution
// Description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "transport=dt_socket,address=") and ((action_process_image_command_line contains "jre1." or action_process_image_command_line contains "jdk1."))) and not (((action_process_image_command_line contains "address=127.0.0.1" or action_process_image_command_line contains "address=localhost"))))
