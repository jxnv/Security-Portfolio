// Title: Suspicious ShellExec_RunDLL Call Via Ordinal
// ID: 8823e85d-31d8-473e-b7f4-92da070f0fc6
// Status: test
// Level: high
// Author: Swachchhanda Shrawan Poudel
// Date: 2024-12-01
// Tags: attack.stealth, attack.t1218.011
// Description: Detects suspicious call to the "ShellExec_RunDLL" exported function of SHELL32.DLL through the ordinal number to launch other commands.
// Adversary might only use the ordinal number in order to bypass existing detection that alert on usage of ShellExec_RunDLL on CommandLine.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line contains "SHELL32.DLL") and ((actor_process_command_line contains "#568" or actor_process_command_line contains "#570" or actor_process_command_line contains "#572" or actor_process_command_line contains "#576"))) and (((action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\msxsl.exe" or action_process_image_path endswith "\\odbcconf.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe")) or (((actor_process_command_line contains "comspec" or actor_process_command_line contains "iex" or actor_process_command_line contains "Invoke-" or actor_process_command_line contains "msiexec" or actor_process_command_line contains "odbcconf" or actor_process_command_line contains "regsvr32")) or ((actor_process_command_line contains "\\Desktop\\" or actor_process_command_line contains "\\ProgramData\\" or actor_process_command_line contains "\\Temp\\" or actor_process_command_line contains "\\Users\\Public\\")))))
