// Title: Start Windows Service Via Net.EXE
// ID: 2a072a96-a086-49fa-bcb5-15cc5a619093
// Status: test
// Level: low
// Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-21
// Tags: attack.execution, attack.t1569.002
// Description: Detects the usage of the "net.exe" command to start a service using the "start" flag
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " start ") and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
