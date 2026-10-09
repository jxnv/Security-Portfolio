// Title: Suspicious Windows Update Agent Empty Cmdline
// ID: 52d097e2-063e-4c9c-8fbb-855c8948d135
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-26
// Tags: attack.stealth, attack.t1036
// Description: Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith "Wuauclt" or action_process_image_command_line endswith "Wuauclt.exe")) and ((action_process_image_path endswith "\\Wuauclt.exe") or (action_process_image_name = "Wuauclt.exe")))
