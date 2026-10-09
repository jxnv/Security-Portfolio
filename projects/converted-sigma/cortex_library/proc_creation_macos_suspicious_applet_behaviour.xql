// Title: Osacompile Execution By Potentially Suspicious Applet/Osascript
// ID: a753a6af-3126-426d-8bd0-26ebbcb92254
// Status: test
// Level: medium
// Author: Sohan G (D4rkCiph3r), Red Canary (Idea)
// Date: 2023-04-03
// Tags: attack.execution, attack.t1059.002
// Description: Detects potential suspicious applet or osascript executing "osacompile".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "/applet" or actor_process_image_path endswith "/osascript") and action_process_image_command_line contains "osacompile")
