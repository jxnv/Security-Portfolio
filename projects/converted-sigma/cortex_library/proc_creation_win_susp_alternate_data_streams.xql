// Title: Execute From Alternate Data Streams
// ID: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-09-01
// Tags: attack.stealth, attack.t1564.004
// Description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "txt:") and (((action_process_image_command_line contains "esentutl " and action_process_image_command_line contains " /y " and action_process_image_command_line contains " /d " and action_process_image_command_line contains " /o ")) or ((action_process_image_command_line contains "makecab " and action_process_image_command_line contains ".cab")) or ((action_process_image_command_line contains "reg " and action_process_image_command_line contains " export ")) or ((action_process_image_command_line contains "regedit " and action_process_image_command_line contains " /E ")) or ((action_process_image_command_line contains "type " and action_process_image_command_line contains " > "))))
