// Title: HackTool - XORDump Execution
// ID: 66e563f9-1cbd-4a22-a957-d8b7c0f44372
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-28
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects suspicious use of XORDump process memory dumping utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\xordump.exe") or ((action_process_image_command_line contains " -process lsass.exe " or action_process_image_command_line contains " -m comsvcs " or action_process_image_command_line contains " -m dbghelp " or action_process_image_command_line contains " -m dbgcore ")))
