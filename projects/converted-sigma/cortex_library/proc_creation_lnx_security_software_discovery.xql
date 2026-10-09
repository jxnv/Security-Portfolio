// Title: Security Software Discovery - Linux
// ID: c9d8b7fd-78e4-44fe-88f6-599135d46d60
// Status: test
// Level: low
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1518.001
// Description: Detects usage of system utilities (only grep and egrep for now) to discover security software discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/grep" or action_process_image_path endswith "/egrep") and (action_process_image_command_line contains "nessusd" or action_process_image_command_line contains "td-agent" or action_process_image_command_line contains "packetbeat" or action_process_image_command_line contains "filebeat" or action_process_image_command_line contains "auditbeat" or action_process_image_command_line contains "osqueryd" or action_process_image_command_line contains "cbagentd" or action_process_image_command_line contains "falcond"))
