// Title: Remote Access Tool - ScreenConnect Installation Execution
// ID: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2021-02-11
// Tags: attack.persistence, attack.initial-access, attack.t1133
// Description: Detects ScreenConnect program starts that establish a remote access to a system.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "e=Access&" and action_process_image_command_line contains "y=Guest&" and action_process_image_command_line contains "&p=" and action_process_image_command_line contains "&c=" and action_process_image_command_line contains "&k="))
