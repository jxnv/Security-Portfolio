// Title: Possible Privilege Escalation via Weak Service Permissions
// ID: d937b75f-a665-4480-88a5-2f20e9f9b22a
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov
// Date: 2019-10-26
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
// Description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\sc.exe" and (IntegrityLevel = "Medium" or IntegrityLevel = "S-1-16-8192")) and (((action_process_image_command_line contains "config" and action_process_image_command_line contains "binPath")) or ((action_process_image_command_line contains "failure" and action_process_image_command_line contains "command"))))
