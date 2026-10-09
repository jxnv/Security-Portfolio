// Title: HackTool - Hydra Password Bruteforce Execution
// ID: aaafa146-074c-11eb-adc1-0242ac120002
// Status: test
// Level: high
// Author: Vasiliy Burov
// Date: 2020-10-05
// Tags: attack.credential-access, attack.t1110, attack.t1110.001
// Description: Detects command line parameters used by Hydra password guessing hack tool
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "-u " and action_process_image_command_line contains "-p ") and (action_process_image_command_line contains "^USER^" or action_process_image_command_line contains "^PASS^"))
