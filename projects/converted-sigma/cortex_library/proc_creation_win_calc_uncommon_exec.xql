// Title: Suspicious Calculator Usage
// ID: 737e618a-a410-49b5-bec3-9e55ff7fbc15
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-02-09
// Tags: attack.stealth, attack.t1036
// Description: Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\calc.exe ") or ((action_process_image_path endswith "\\calc.exe") and not (((action_process_image_path contains ":\\Windows\\System32\\" or action_process_image_path contains ":\\Windows\\SysWOW64\\" or action_process_image_path contains ":\\Windows\\WinSxS\\")))))
