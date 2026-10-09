// Title: Scheduled Task Creation Via Schtasks.EXE
// ID: 92626ddd-662c-49e3-ac59-f6535f12d189
// Status: test
// Level: low
// Author: Florian Roth (Nextron Systems)
// Date: 2019-01-16
// Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005, attack.s0111, car.2013-08-001, stp.1u
// Description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\schtasks.exe" and action_process_image_command_line contains " /create ") and not (((action_process_username contains "AUTHORI" or action_process_username contains "AUTORI"))) and not (((actor_process_image_path = "C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe" or actor_process_image_path = "C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe") and (action_process_image_path = "C:\\Windows\\System32\\schtasks.exe" or action_process_image_path = "C:\\Windows\\SysWOW64\\schtasks.exe") and action_process_image_command_line contains "Microsoft\\Office\\Office Performance Monitor")))
