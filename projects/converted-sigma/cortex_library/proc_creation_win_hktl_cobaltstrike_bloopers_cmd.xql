// Title: Operator Bloopers Cobalt Strike Commands
// ID: 647c7b9e-d784-4fda-b9a0-45c565a7b729
// Status: test
// Level: high
// Author: _pete_0, TheDFIRReport
// Date: 2022-05-06
// Tags: attack.execution, attack.t1059.003, stp.1u
// Description: Detects use of Cobalt Strike commands accidentally entered in the CMD shell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line startswith "cmd " or action_process_image_command_line startswith "cmd.exe" or action_process_image_command_line startswith "c:\\windows\\system32\\cmd.exe") and (action_process_image_command_line contains "psinject" or action_process_image_command_line contains "spawnas" or action_process_image_command_line contains "make_token" or action_process_image_command_line contains "remote-exec" or action_process_image_command_line contains "rev2self" or action_process_image_command_line contains "dcsync" or action_process_image_command_line contains "logonpasswords" or action_process_image_command_line contains "execute-assembly" or action_process_image_command_line contains "getsystem")) and ((action_process_image_name = "Cmd.Exe") or (action_process_image_path endswith "\\cmd.exe")))
