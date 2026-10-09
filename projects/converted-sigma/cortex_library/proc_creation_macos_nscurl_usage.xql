// Title: File Download Via Nscurl - MacOS
// ID: 6d8a7cf1-8085-423b-b87d-7e880faabbdf
// Status: test
// Level: medium
// Author: Daniel Cortez
// Date: 2024-06-04
// Tags: attack.command-and-control, attack.t1105
// Description: Detects the execution of the nscurl utility in order to download files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/nscurl" and (action_process_image_command_line contains "--download " or action_process_image_command_line contains "--download-directory " or action_process_image_command_line contains "--output " or action_process_image_command_line contains "-dir " or action_process_image_command_line contains "-dl " or action_process_image_command_line contains "-ld" or action_process_image_command_line contains "-o "))
