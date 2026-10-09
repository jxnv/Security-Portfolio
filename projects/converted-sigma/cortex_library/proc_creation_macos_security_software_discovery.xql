// Title: Security Software Discovery - MacOs
// ID: 0ed75b9c-c73b-424d-9e7d-496cd565fbe0
// Status: test
// Level: medium
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1518.001
// Description: Detects usage of system utilities (only grep for now) to discover security software discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path = "/usr/bin/grep") and (((action_process_image_command_line contains "nessusd" or action_process_image_command_line contains "santad" or action_process_image_command_line contains "CbDefense" or action_process_image_command_line contains "falcond" or action_process_image_command_line contains "td-agent" or action_process_image_command_line contains "packetbeat" or action_process_image_command_line contains "filebeat" or action_process_image_command_line contains "auditbeat" or action_process_image_command_line contains "osqueryd" or action_process_image_command_line contains "BlockBlock" or action_process_image_command_line contains "LuLu")) or ((action_process_image_command_line contains "Little" and action_process_image_command_line contains "Snitch"))))
