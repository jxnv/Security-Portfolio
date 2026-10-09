// Title: Potentially Suspicious JWT Token Search Via CLI
// ID: 6d3a3952-6530-44a3-8554-cf17c116c615
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), kagebunsher
// Date: 2022-10-25
// Tags: attack.credential-access, attack.t1528, attack.t1552.001
// Description: Detects potentially suspicious search for JWT tokens via CLI by looking for the string "eyJ0eX" or "eyJhbG".
// JWT tokens are often used for access-tokens across various applications and services like Microsoft 365, Azure, AWS, Google Cloud, and others.
// Threat actors may search for these tokens to steal them for lateral movement or privilege escalation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "eyJ0eXAiOi" or action_process_image_command_line contains "eyJhbGciOi" or action_process_image_command_line contains " eyJ0eX" or action_process_image_command_line contains " \"eyJ0eX\"" or action_process_image_command_line contains " 'eyJ0eX'" or action_process_image_command_line contains " eyJhbG" or action_process_image_command_line contains " \"eyJhbG\"" or action_process_image_command_line contains " 'eyJhbG'")) and ((action_process_image_command_line contains "find " or action_process_image_command_line contains "find.exe" or action_process_image_command_line contains "findstr" or action_process_image_command_line contains "select-string " or action_process_image_command_line contains "strings")))
