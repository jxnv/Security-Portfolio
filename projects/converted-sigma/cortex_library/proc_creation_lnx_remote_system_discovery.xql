// Title: Linux Remote System Discovery
// ID: 11063ec2-de63-4153-935e-b1a8b9e616f1
// Status: test
// Level: low
// Author: Alejandro Ortuno, oscd.community
// Date: 2020-10-22
// Tags: attack.discovery, attack.t1018
// Description: Detects the enumeration of other remote systems.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/arp" and action_process_image_command_line contains "-a") or (action_process_image_path endswith "/ping" and (action_process_image_command_line contains " 10." or action_process_image_command_line contains " 192.168." or action_process_image_command_line contains " 172.16." or action_process_image_command_line contains " 172.17." or action_process_image_command_line contains " 172.18." or action_process_image_command_line contains " 172.19." or action_process_image_command_line contains " 172.20." or action_process_image_command_line contains " 172.21." or action_process_image_command_line contains " 172.22." or action_process_image_command_line contains " 172.23." or action_process_image_command_line contains " 172.24." or action_process_image_command_line contains " 172.25." or action_process_image_command_line contains " 172.26." or action_process_image_command_line contains " 172.27." or action_process_image_command_line contains " 172.28." or action_process_image_command_line contains " 172.29." or action_process_image_command_line contains " 172.30." or action_process_image_command_line contains " 172.31." or action_process_image_command_line contains " 127." or action_process_image_command_line contains " 169.254.")))
