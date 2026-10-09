// Title: PUA - AdvancedRun Execution
// ID: d2b749ee-4225-417e-b20e-a8d2193cbb84
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-20
// Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1564.003, attack.t1134.002, attack.t1059.003
// Description: Detects the execution of AdvancedRun utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = "AdvancedRun.exe") or ((action_process_image_command_line contains " /EXEFilename " and action_process_image_command_line contains " /Run")) or ((action_process_image_command_line contains " /WindowState 0" and action_process_image_command_line contains " /RunAs " and action_process_image_command_line contains " /CommandLine ")))
