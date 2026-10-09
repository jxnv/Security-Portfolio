// Title: Binary Padding - MacOS
// ID: 95361ce5-c891-4b0a-87ca-e24607884a96
// Status: test
// Level: high
// Author: Igor Fits, Mikhail Larin, oscd.community
// Date: 2020-10-19
// Tags: attack.stealth, attack.t1027.001
// Description: Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/dd" and (action_process_image_command_line contains "if=/dev/zero" or action_process_image_command_line contains "if=/dev/random" or action_process_image_command_line contains "if=/dev/urandom")) or (action_process_image_path endswith "/truncate" and action_process_image_command_line contains "-s +"))
