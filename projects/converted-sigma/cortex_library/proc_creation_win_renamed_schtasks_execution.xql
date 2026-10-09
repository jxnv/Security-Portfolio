// Title: Renamed Schtasks Execution
// ID: f91e51c9-f344-4b32-969b-0b6f6b8537d4
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-27
// Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1036.003, attack.t1053.005
// Description: Detects the execution of renamed schtasks.exe binary, which is a legitimate Windows utility used for scheduling tasks.
// One of the very common persistence techniques is schedule malicious tasks using schtasks.exe.
// Since, it is heavily abused, it is also heavily monitored by security products. To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_command_line contains " /tn " or action_process_image_command_line contains " /tr " or action_process_image_command_line contains " /sc " or action_process_image_command_line contains " /st " or action_process_image_command_line contains " /ru " or action_process_image_command_line contains " /fo ")) and ((action_process_image_command_line contains " /create " or action_process_image_command_line contains " /delete " or action_process_image_command_line contains " /query " or action_process_image_command_line contains " /change " or action_process_image_command_line contains " /run " or action_process_image_command_line contains " /end "))) and not ((action_process_image_command_line contains "schtasks")) and not (((action_process_image_command_line contains "openfiles" and action_process_image_command_line contains " /query " and action_process_image_command_line contains " /fo")))) or ((action_process_image_name = "schtasks.exe") and not ((action_process_image_path endswith "\\schtasks.exe"))))
