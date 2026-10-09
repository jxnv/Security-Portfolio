// Title: Disable Windows Defender AV Security Monitoring
// ID: a7ee1722-c3c5-aeff-3212-c777e4733217
// Status: test
// Level: high
// Author: ok @securonix invrep-de, oscd.community, frack113
// Date: 2020-10-12
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects attackers attempting to disable Windows Defender using Powershell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "-DisableBehaviorMonitoring $true" or action_process_image_command_line contains "-DisableRuntimeMonitoring $true"))) or (((action_process_image_path endswith "\\sc.exe") or (action_process_image_name = "sc.exe")) and (((action_process_image_command_line contains "delete" and action_process_image_command_line contains "WinDefend")) or ((action_process_image_command_line contains "config" and action_process_image_command_line contains "WinDefend" and action_process_image_command_line contains "start=disabled")) or ((action_process_image_command_line contains "stop" and action_process_image_command_line contains "WinDefend")))))
