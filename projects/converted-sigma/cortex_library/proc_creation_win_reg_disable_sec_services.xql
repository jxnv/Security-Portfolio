// Title: Security Service Disabled Via Reg.EXE
// ID: 5e95028c-5229-4214-afae-d653d573d0ec
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
// Date: 2021-07-14
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "d 4" and action_process_image_command_line contains "v Start") and (action_process_image_command_line contains "\\AppIDSvc" or action_process_image_command_line contains "\\MsMpSvc" or action_process_image_command_line contains "\\NisSrv" or action_process_image_command_line contains "\\SecurityHealthService" or action_process_image_command_line contains "\\Sense" or action_process_image_command_line contains "\\UsoSvc" or action_process_image_command_line contains "\\WdBoot" or action_process_image_command_line contains "\\WdFilter" or action_process_image_command_line contains "\\WdNisDrv" or action_process_image_command_line contains "\\WdNisSvc" or action_process_image_command_line contains "\\WinDefend" or action_process_image_command_line contains "\\wscsvc" or action_process_image_command_line contains "\\wuauserv")) and ((action_process_image_command_line contains "reg" and action_process_image_command_line contains "add")))
