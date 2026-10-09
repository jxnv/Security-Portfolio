// Title: Obfuscated IP Via CLI
// ID: 56d19cb4-6414-4769-9644-1ed35ffbb148
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
// Date: 2022-08-03
// Tags: attack.discovery
// Description: Detects usage of an encoded/obfuscated version of an IP address (hex, octal, etc.) via command line
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\ping.exe" or action_process_image_path endswith "\\arp.exe")) and (((action_process_image_command_line contains " 0x" or action_process_image_command_line contains "//0x" or action_process_image_command_line contains ".0x" or action_process_image_command_line contains ".00x")) or ((action_process_image_command_line contains "http://%" and action_process_image_command_line contains "%2e")) or ((action_process_image_command_line ~= "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}") or (action_process_image_command_line ~= "https?://[0-9]{1,3}\\.0[0-9]{3,7}") or (action_process_image_command_line ~= "https?://0[0-9]{3,11}") or (action_process_image_command_line ~= "https?://(?:0[0-9]{1,11}\\.){3}0[0-9]{1,11}") or (action_process_image_command_line ~= "https?://0[0-9]{1,11}") or (action_process_image_command_line ~= " [0-7]{7,13}"))) and not ((action_process_image_command_line ~= "https?://(?:(?:25[0-5]|(?:2[0-4]|1\\d|[1-9])?\\d)(?:\\.|\\b)){4}")))
