// Title: File and Directory Discovery - MacOS
// ID: 089dbdf6-b960-4bcc-90e3-ffc3480c20f6
// Status: test
// Level: informational
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1083
// Description: Detects usage of system utilities to discover files and directories
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path = "/usr/bin/file" and action_process_image_command_line ~= "(.){200,}") or (action_process_image_path = "/usr/bin/find") or (action_process_image_path = "/usr/bin/mdfind") or (action_process_image_path = "/bin/ls" and action_process_image_command_line contains "-R") or 1=1)
