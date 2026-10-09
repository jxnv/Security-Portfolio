// Title: VMToolsd Suspicious Child Process
// ID: 5687f942-867b-4578-ade7-1e341c46e99a
// Status: test
// Level: high
// Author: bohops, Bhabesh Raj
// Date: 2021-10-08
// Tags: attack.execution, attack.persistence, attack.t1059
// Description: Detects suspicious child process creations of VMware Tools process which may indicate persistence setup
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "cscript.exe" or action_process_image_name = "MSHTA.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "REGSVR32.EXE" or action_process_image_name = "RUNDLL32.EXE" or action_process_image_name = "wscript.exe"))) and (actor_process_image_path endswith "\\vmtoolsd.exe")) and not (((action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line = "") or (action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line = null) or (action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "\\VMware\\VMware Tools\\poweron-vm-default.bat" or action_process_image_command_line contains "\\VMware\\VMware Tools\\poweroff-vm-default.bat" or action_process_image_command_line contains "\\VMware\\VMware Tools\\resume-vm-default.bat" or action_process_image_command_line contains "\\VMware\\VMware Tools\\suspend-vm-default.bat")))))
