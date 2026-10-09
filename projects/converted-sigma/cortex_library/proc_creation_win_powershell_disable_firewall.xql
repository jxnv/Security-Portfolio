// Title: Windows Firewall Disabled via PowerShell
// ID: 12f6b752-042d-483e-bf9c-915a6d06ad75
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-14
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects attempts to disable the Windows Firewall using PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Set-NetFirewallProfile " and action_process_image_command_line contains " -Enabled " and action_process_image_command_line contains " False")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\powershell_ise.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains " -All " or action_process_image_command_line contains "Public" or action_process_image_command_line contains "Domain" or action_process_image_command_line contains "Private")))
