// Title: Compress Data and Lock With Password for Exfiltration With 7-ZIP
// ID: 9fbf5927-5261-4284-a71d-f681029ea574
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-27
// Tags: attack.collection, attack.t1560.001
// Description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " a " or action_process_image_command_line contains " u ")) and ((Description contains "7-Zip") or ((action_process_image_path endswith "\\7z.exe" or action_process_image_path endswith "\\7zr.exe" or action_process_image_path endswith "\\7za.exe")) or ((action_process_image_name = "7z.exe" or action_process_image_name = "7za.exe" or action_process_image_name = "7zr.exe"))) and (action_process_image_command_line contains " -p"))
