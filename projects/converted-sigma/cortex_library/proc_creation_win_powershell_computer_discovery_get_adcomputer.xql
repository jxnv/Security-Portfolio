// Title: Computer Discovery And Export Via Get-ADComputer Cmdlet
// ID: 435e10e4-992a-4281-96f3-38b11106adde
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-11-10
// Tags: attack.discovery, attack.t1033
// Description: Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Get-ADComputer " and action_process_image_command_line contains " -Filter \\*") and (action_process_image_command_line contains " > " or action_process_image_command_line contains " | Select " or action_process_image_command_line contains "Out-File" or action_process_image_command_line contains "Set-Content" or action_process_image_command_line contains "Add-Content")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
