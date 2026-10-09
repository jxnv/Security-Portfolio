// Title: Linux Base64 Encoded Shebang In CLI
// ID: fe2f9663-41cb-47e2-b954-8a228f3b9dff
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.stealth, attack.t1140
// Description: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "IyEvYmluL2Jhc2" or action_process_image_command_line contains "IyEvYmluL2Rhc2" or action_process_image_command_line contains "IyEvYmluL3pza" or action_process_image_command_line contains "IyEvYmluL2Zpc2" or action_process_image_command_line contains "IyEvYmluL3No"))
