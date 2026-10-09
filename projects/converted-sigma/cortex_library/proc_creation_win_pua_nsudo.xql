// Title: PUA - NSudo Execution
// ID: 771d1eb5-9587-4568-95fb-9ec44153a012
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali
// Date: 2022-01-24
// Tags: attack.execution, attack.t1569.002, attack.s0029
// Description: Detects the use of NSudo tool for command execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-U:S " or action_process_image_command_line contains "-U:T " or action_process_image_command_line contains "-U:E " or action_process_image_command_line contains "-P:E " or action_process_image_command_line contains "-M:S " or action_process_image_command_line contains "-M:H " or action_process_image_command_line contains "-U=S " or action_process_image_command_line contains "-U=T " or action_process_image_command_line contains "-U=E " or action_process_image_command_line contains "-P=E " or action_process_image_command_line contains "-M=S " or action_process_image_command_line contains "-M=H " or action_process_image_command_line contains "-ShowWindowMode:Hide")) and (((action_process_image_path endswith "\\NSudo.exe" or action_process_image_path endswith "\\NSudoLC.exe" or action_process_image_path endswith "\\NSudoLG.exe")) or ((action_process_image_name = "NSudo.exe" or action_process_image_name = "NSudoLC.exe" or action_process_image_name = "NSudoLG.exe"))))
