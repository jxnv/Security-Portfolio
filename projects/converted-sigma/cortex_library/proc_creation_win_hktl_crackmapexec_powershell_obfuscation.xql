// Title: HackTool - CrackMapExec PowerShell Obfuscation
// ID: 6f8b3439-a203-45dc-a88b-abf57ea15ccf
// Status: test
// Level: high
// Author: Thomas Patzke
// Date: 2020-05-22
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027.005
// Description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "join*split" or action_process_image_command_line contains "( $ShellId[1]+$ShellId[13]+'x')" or action_process_image_command_line contains "( $PSHome[*]+$PSHOME[*]+" or action_process_image_command_line contains "( $env:Public[13]+$env:Public[5]+'x')" or action_process_image_command_line contains "( $env:ComSpec[4,*,25]-Join'')" or action_process_image_command_line contains "[1,3]+'x'-Join'')")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
