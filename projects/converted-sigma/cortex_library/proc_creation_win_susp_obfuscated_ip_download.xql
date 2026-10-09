// Title: Obfuscated IP Download Activity
// ID: cb5a2333-56cf-4562-8fcb-22ba1bca728d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
// Date: 2022-08-03
// Tags: attack.discovery
// Description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Invoke-WebRequest" or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "Invoke-RestMethod" or action_process_image_command_line contains "irm " or action_process_image_command_line contains "wget " or action_process_image_command_line contains "curl " or action_process_image_command_line contains "DownloadFile" or action_process_image_command_line contains "DownloadString")) and (((action_process_image_command_line contains " 0x" or action_process_image_command_line contains "//0x" or action_process_image_command_line contains ".0x" or action_process_image_command_line contains ".00x")) or ((action_process_image_command_line contains "http://%" and action_process_image_command_line contains "%2e")) or ((action_process_image_command_line ~= "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}") or (action_process_image_command_line ~= "https?://[0-9]{1,3}\\.0[0-9]{3,7}") or (action_process_image_command_line ~= "https?://0[0-9]{3,11}") or (action_process_image_command_line ~= "https?://(?:0[0-9]{1,11}\\.){3}0[0-9]{1,11}") or (action_process_image_command_line ~= "https?://0[0-9]{1,11}") or (action_process_image_command_line ~= " [0-7]{7,13}"))) and not ((action_process_image_command_line ~= "https?://(?:(?:25[0-5]|(?:2[0-4]|1\\d|[1-9])?\\d)(?:\\.|\\b)){4}")))
