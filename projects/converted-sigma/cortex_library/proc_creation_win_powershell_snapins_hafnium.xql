// Title: Exchange PowerShell Snap-Ins Usage
// ID: 25676e10-2121-446e-80a4-71ff8506af47
// Status: test
// Level: high
// Author: FPT.EagleEye, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-03-03
// Tags: attack.execution, attack.t1059.001, attack.collection, attack.t1114
// Description: Detects adding and using Exchange PowerShell snap-ins to export mailbox data. As seen used by HAFNIUM and APT27
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Add-PSSnapin") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "Microsoft.Exchange.Powershell.Snapin" or action_process_image_command_line contains "Microsoft.Exchange.Management.PowerShell.SnapIn"))) and not ((actor_process_image_path = "C:\\Windows\\System32\\msiexec.exe" and action_process_image_command_line contains "$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null")))
