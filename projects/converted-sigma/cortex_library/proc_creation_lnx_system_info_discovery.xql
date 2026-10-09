// Title: System Information Discovery
// ID: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
// Status: stable
// Level: informational
// Author: Ömer Günal, oscd.community
// Date: 2020-10-08
// Tags: attack.discovery, attack.t1082
// Description: Detects system information discovery commands
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/uname" or action_process_image_path endswith "/hostname" or action_process_image_path endswith "/uptime" or action_process_image_path endswith "/lspci" or action_process_image_path endswith "/dmidecode" or action_process_image_path endswith "/lscpu" or action_process_image_path endswith "/lsmod"))
