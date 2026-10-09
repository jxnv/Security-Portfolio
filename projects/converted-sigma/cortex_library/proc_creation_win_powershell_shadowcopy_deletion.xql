// Title: Deletion of Volume Shadow Copies via WMI with PowerShell
// ID: 21ff4ca9-f13a-41ad-b828-0077b2af2e40
// Status: test
// Level: high
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-20
// Tags: attack.impact, attack.t1490
// Description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".Delete()" or action_process_image_command_line contains "Remove-WmiObject" or action_process_image_command_line contains "rwmi" or action_process_image_command_line contains "Remove-CimInstance" or action_process_image_command_line contains "rcim")) and ((action_process_image_command_line contains "Get-WmiObject" or action_process_image_command_line contains "gwmi" or action_process_image_command_line contains "Get-CimInstance" or action_process_image_command_line contains "gcim")) and (action_process_image_command_line contains "Win32_ShadowCopy"))
