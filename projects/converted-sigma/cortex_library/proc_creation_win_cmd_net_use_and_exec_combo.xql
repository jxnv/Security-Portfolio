// Title: Suspicious File Execution From Internet Hosted WebDav Share
// ID: f0507c0f-a3a2-40f5-acc6-7f543c334993
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-09-01
// Tags: attack.execution, attack.t1059.001
// Description: Detects the execution of the "net use" command to mount a WebDAV server and then immediately execute some content in it. As seen being used in malicious LNK files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " net use http" and action_process_image_command_line contains "& start /b " and action_process_image_command_line contains "\\DavWWWRoot\\")) and ((action_process_image_command_line contains ".exe " or action_process_image_command_line contains ".dll " or action_process_image_command_line contains ".bat " or action_process_image_command_line contains ".vbs " or action_process_image_command_line contains ".ps1 ")) and ((action_process_image_path contains "\\cmd.exe") or (action_process_image_name = "Cmd.EXE")))
