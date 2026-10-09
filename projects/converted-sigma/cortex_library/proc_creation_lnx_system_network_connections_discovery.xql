// Title: System Network Connections Discovery - Linux
// ID: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79
// Status: test
// Level: low
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1049
// Description: Detects usage of system utilities to discover system network connections
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/who" or action_process_image_path endswith "/w" or action_process_image_path endswith "/last" or action_process_image_path endswith "/lsof" or action_process_image_path endswith "/netstat")) and not ((actor_process_command_line contains "/usr/bin/landscape-sysinfo" and action_process_image_path endswith "/who")))
