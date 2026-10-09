// Title: Potential Persistence Attempt Via Existing Service Tampering
// ID: 38879043-7e1e-47a9-8d46-6bec88e201df
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-09-29
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1543.003, attack.t1574.011
// Description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "sc " and action_process_image_command_line contains "config " and action_process_image_command_line contains "binpath=")) or ((action_process_image_command_line contains "sc " and action_process_image_command_line contains "failure" and action_process_image_command_line contains "command="))) or (((action_process_image_command_line contains ".sh" or action_process_image_command_line contains ".exe" or action_process_image_command_line contains ".dll" or action_process_image_command_line contains ".bin$" or action_process_image_command_line contains ".bat" or action_process_image_command_line contains ".cmd" or action_process_image_command_line contains ".js" or action_process_image_command_line contains ".msh$" or action_process_image_command_line contains ".reg$" or action_process_image_command_line contains ".scr" or action_process_image_command_line contains ".ps" or action_process_image_command_line contains ".vb" or action_process_image_command_line contains ".jar" or action_process_image_command_line contains ".pl")) and (((action_process_image_command_line contains "reg " and action_process_image_command_line contains "add " and action_process_image_command_line contains "FailureCommand")) or ((action_process_image_command_line contains "reg " and action_process_image_command_line contains "add " and action_process_image_command_line contains "ImagePath")))))
