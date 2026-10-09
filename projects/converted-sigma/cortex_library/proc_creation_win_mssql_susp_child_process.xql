// Title: Suspicious Child Process Of SQL Server
// ID: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
// Status: test
// Level: high
// Author: FPT.EagleEye Team, wagga
// Date: 2020-12-11
// Tags: attack.t1505.003, attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\sqlservr.exe" and (action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\netstat.exe" or action_process_image_path endswith "\\nltest.exe" or action_process_image_path endswith "\\ping.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\tasklist.exe" or action_process_image_path endswith "\\wsl.exe")) and not ((actor_process_image_path startswith "C:\\Program Files\\Microsoft SQL Server\\" and actor_process_image_path endswith "DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe" and action_process_image_path = "C:\\Windows\\System32\\cmd.exe" and action_process_image_command_line startswith "\"C:\\Windows\\system32\\cmd.exe\" ")))
