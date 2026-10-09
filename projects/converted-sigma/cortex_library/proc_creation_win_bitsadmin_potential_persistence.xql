// Title: Monitoring For Persistence Via BITS
// ID: b9cbbc17-d00d-4e3d-a827-b06d03d2380d
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-10-29
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
// Description: BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished.
// When the job runs on the system the command specified in the BITS job will be executed.
// This can be abused by actors to create a backdoor within the system and for persistence.
// It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\bitsadmin.exe") or (action_process_image_name = "bitsadmin.exe")) and (((action_process_image_command_line contains "/SetNotifyCmdLine") and ((action_process_image_command_line contains "%COMSPEC%" or action_process_image_command_line contains "cmd.exe" or action_process_image_command_line contains "regsvr32.exe"))) or ((action_process_image_command_line contains "/Addfile") and ((action_process_image_command_line contains "http:" or action_process_image_command_line contains "https:" or action_process_image_command_line contains "ftp:" or action_process_image_command_line contains "ftps:")))))
