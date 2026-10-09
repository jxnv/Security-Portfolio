// Title: Local Groups Discovery - MacOs
// ID: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
// Status: test
// Level: informational
// Author: Ömer Günal, Alejandro Ortuno, oscd.community
// Date: 2020-10-11
// Tags: attack.discovery, attack.t1069.001
// Description: Detects enumeration of local system groups
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/dscacheutil" and (action_process_image_command_line contains "-q" and action_process_image_command_line contains "group")) or (action_process_image_path endswith "/cat" and action_process_image_command_line contains "/etc/group") or (action_process_image_path endswith "/dscl" and (action_process_image_command_line contains "-list" and action_process_image_command_line contains "/groups")))
