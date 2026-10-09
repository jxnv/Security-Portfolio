// Title: Suspicious Network Connection Binary No CommandLine
// ID: 20384606-a124-4fec-acbb-8bd373728613
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-07-03
// Tags: attack.stealth
// Description: Detects suspicious network connections made by a well-known Windows binary run with no command line parameters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and (action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\dllhost.exe") and (action_process_image_command_line endswith "\\regsvr32.exe" or action_process_image_command_line endswith "\\rundll32.exe" or action_process_image_command_line endswith "\\dllhost.exe")) and not (((action_process_image_command_line = "") or (action_process_image_command_line = null))))
