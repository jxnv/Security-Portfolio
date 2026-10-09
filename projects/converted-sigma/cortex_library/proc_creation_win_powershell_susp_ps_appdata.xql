// Title: PowerShell Script Run in AppData
// ID: ac175779-025a-4f12-98b0-acdaeb77ea85
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
// Date: 2019-01-09
// Tags: attack.execution, attack.t1059.001
// Description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "powershell.exe" or action_process_image_command_line contains "\\powershell" or action_process_image_command_line contains "\\pwsh" or action_process_image_command_line contains "pwsh.exe")) and ((action_process_image_command_line contains "/c " and action_process_image_command_line contains "\\AppData\\") and (action_process_image_command_line contains "Local\\" or action_process_image_command_line contains "Roaming\\")))
