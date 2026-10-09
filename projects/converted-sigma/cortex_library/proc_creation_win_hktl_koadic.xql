// Title: HackTool - Koadic Execution
// ID: 5cddf373-ef00-4112-ad72-960ac29bac34
// Status: test
// Level: high
// Author: wagga, Jonhnathan Ribeiro, oscd.community
// Date: 2020-01-12
// Tags: attack.execution, attack.t1059.003, attack.t1059.005, attack.t1059.007
// Description: Detects command line parameters used by Koadic hack tool
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/q" and action_process_image_command_line contains "/c" and action_process_image_command_line contains "chcp")) and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")))
