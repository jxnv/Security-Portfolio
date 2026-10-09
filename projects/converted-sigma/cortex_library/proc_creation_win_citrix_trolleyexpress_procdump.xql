// Title: Process Access via TrolleyExpress Exclusion
// ID: 4c0aaedc-154c-4427-ada0-d80ef9c9deb6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-10
// Tags: attack.stealth, attack.t1218.011, attack.credential-access, attack.t1003.001
// Description: Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\TrolleyExpress 7" or action_process_image_command_line contains "\\TrolleyExpress 8" or action_process_image_command_line contains "\\TrolleyExpress 9" or action_process_image_command_line contains "\\TrolleyExpress.exe 7" or action_process_image_command_line contains "\\TrolleyExpress.exe 8" or action_process_image_command_line contains "\\TrolleyExpress.exe 9" or action_process_image_command_line contains "\\TrolleyExpress.exe -ma ")) or ((action_process_image_path endswith "\\TrolleyExpress.exe") and not (((action_process_image_name = null) or (action_process_image_name contains "CtxInstall")))))
