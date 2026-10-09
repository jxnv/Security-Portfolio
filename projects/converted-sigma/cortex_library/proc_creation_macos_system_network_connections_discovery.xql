// Title: System Network Connections Discovery - MacOs
// ID: 9a7a0393-2144-4626-9bf1-7c2f5a7321db
// Status: test
// Level: informational
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1049
// Description: Detects usage of system utilities to discover system network connections
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/who" or action_process_image_path endswith "/w" or action_process_image_path endswith "/last" or action_process_image_path endswith "/lsof" or action_process_image_path endswith "/netstat"))
