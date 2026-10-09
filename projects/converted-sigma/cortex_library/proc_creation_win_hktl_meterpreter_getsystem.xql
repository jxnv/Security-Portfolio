// Title: Potential Meterpreter/CobaltStrike Activity
// ID: 15619216-e993-4721-b590-4c520615a67d
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Ecco, Florian Roth
// Date: 2019-10-26
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
// Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\services.exe") and (((action_process_image_command_line contains "/c" and action_process_image_command_line contains "echo" and action_process_image_command_line contains "\\pipe\\") and (action_process_image_command_line contains "cmd" or action_process_image_command_line contains "%COMSPEC%")) or ((action_process_image_command_line contains "rundll32" and action_process_image_command_line contains ".dll,a" and action_process_image_command_line contains "/p:"))) and not ((action_process_image_command_line contains "MpCmdRun")))
