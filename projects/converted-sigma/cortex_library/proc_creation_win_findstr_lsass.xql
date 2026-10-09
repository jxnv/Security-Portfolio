// Title: LSASS Process Reconnaissance Via Findstr.EXE
// ID: fe63010f-8823-4864-a96b-a7b4a0f7b929
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-12
// Tags: attack.credential-access, attack.t1552.006
// Description: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "lsass") and (((action_process_image_path endswith "\\find.exe" or action_process_image_path endswith "\\findstr.exe")) or ((action_process_image_name = "FIND.EXE" or action_process_image_name = "FINDSTR.EXE")))) or ((action_process_image_command_line contains " /i \"lsass" or action_process_image_command_line contains " /i lsass.exe" or action_process_image_command_line contains "findstr \"lsass" or action_process_image_command_line contains "findstr lsass" or action_process_image_command_line contains "findstr.exe \"lsass" or action_process_image_command_line contains "findstr.exe lsass")))
