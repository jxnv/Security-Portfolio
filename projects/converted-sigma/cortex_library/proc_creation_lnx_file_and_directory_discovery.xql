// Title: File and Directory Discovery - Linux
// ID: d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72
// Status: test
// Level: informational
// Author: Daniil Yugoslavskiy, oscd.community, CheraghiMilad
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1083
// Description: Detects usage of system utilities such as "find", "tree", "findmnt", etc, to discover files, directories and network shares.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/file" and action_process_image_command_line ~= "(.){200,}") or (action_process_image_path endswith "/find") or (action_process_image_path endswith "/findmnt") or (action_process_image_path endswith "/mlocate") or (action_process_image_path endswith "/ls" and action_process_image_command_line contains "-R") or (action_process_image_path endswith "/tree"))
