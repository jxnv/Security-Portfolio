// Title: Abused Debug Privilege by Arbitrary Parent Processes
// ID: d522eca2-2973-4391-a3e0-ef0374321dae
// Status: test
// Level: high
// Author: Semanur Guneysu @semanurtg, oscd.community
// Date: 2020-10-28
// Tags: attack.privilege-escalation, attack.t1548
// Description: Detection of unusual child processes by different system processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cmd.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "Cmd.Exe"))) and ((actor_process_image_path endswith "\\winlogon.exe" or actor_process_image_path endswith "\\services.exe" or actor_process_image_path endswith "\\lsass.exe" or actor_process_image_path endswith "\\csrss.exe" or actor_process_image_path endswith "\\smss.exe" or actor_process_image_path endswith "\\wininit.exe" or actor_process_image_path endswith "\\spoolsv.exe" or actor_process_image_path endswith "\\searchindexer.exe") and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI"))) and not (((action_process_image_command_line contains " route " and action_process_image_command_line contains " ADD "))))
