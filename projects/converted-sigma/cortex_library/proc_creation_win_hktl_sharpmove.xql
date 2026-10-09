// Title: HackTool - SharpMove Tool Execution
// ID: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
// Status: test
// Level: high
// Author: Luca Di Bartolomeo (CrimpSec)
// Date: 2024-01-29
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\SharpMove.exe") or (action_process_image_name = "SharpMove.exe")) or (((action_process_image_command_line contains "action=create" or action_process_image_command_line contains "action=dcom" or action_process_image_command_line contains "action=executevbs" or action_process_image_command_line contains "action=hijackdcom" or action_process_image_command_line contains "action=modschtask" or action_process_image_command_line contains "action=modsvc" or action_process_image_command_line contains "action=query" or action_process_image_command_line contains "action=scm" or action_process_image_command_line contains "action=startservice" or action_process_image_command_line contains "action=taskscheduler")) and (action_process_image_command_line contains "computername=")))
