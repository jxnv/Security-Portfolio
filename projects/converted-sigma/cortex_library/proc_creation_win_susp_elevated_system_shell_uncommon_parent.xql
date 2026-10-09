// Title: Elevated System Shell Spawned From Uncommon Parent Location
// ID: 178e615d-e666-498b-9630-9ed363038101
// Status: test
// Level: medium
// Author: frack113, Tim Shelton (update fp)
// Date: 2022-12-05
// Tags: attack.privilege-escalation, attack.execution, attack.t1059
// Description: Detects when a shell program such as the Windows command prompt or PowerShell is launched with system privileges from a uncommon parent location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cmd.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "powershell_ise.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "Cmd.Exe"))) and ((action_process_username contains "AUTHORI" or action_process_username contains "AUTORI") and LogonId = "0x3e7")) and not ((((actor_process_image_path contains ":\\Program Files (x86)\\" or actor_process_image_path contains ":\\Program Files\\" or actor_process_image_path contains ":\\ProgramData\\" or actor_process_image_path contains ":\\Windows\\System32\\" or actor_process_image_path contains ":\\Windows\\SysWOW64\\" or actor_process_image_path contains ":\\Windows\\Temp\\" or actor_process_image_path contains ":\\Windows\\WinSxS\\")) or ((actor_process_image_path = "" or actor_process_image_path = "-")) or (actor_process_image_path = null))) and not (((action_process_image_command_line contains ":\\WINDOWS\\system32\\cmd.exe /c \"" and CurrentDirectory contains ":\\WINDOWS\\Temp\\asgard2-agent\\") or (actor_process_image_path contains ":\\IBM\\SpectrumProtect\\webserver\\scripts\\" and action_process_image_command_line contains ":\\IBM\\SpectrumProtect\\webserver\\scripts\\") or (actor_process_image_path endswith ":\\ManageEngine\\ADManager Plus\\pgsql\\bin\\postgres.exe" and action_process_image_path endswith "\\cmd.exe"))))
