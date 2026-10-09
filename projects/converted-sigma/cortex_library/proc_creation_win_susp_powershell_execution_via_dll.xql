// Title: Potential PowerShell Execution Via DLL
// ID: 6812a10b-60ea-420c-832f-dfcc33b646ba
// Status: test
// Level: high
// Author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
// Date: 2018-08-25
// Tags: attack.stealth, attack.t1218.011
// Description: Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll.
// This detection assumes that PowerShell commands are passed via the CommandLine.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Default.GetString" or action_process_image_command_line contains "DownloadString" or action_process_image_command_line contains "FromBase64String" or action_process_image_command_line contains "ICM " or action_process_image_command_line contains "IEX " or action_process_image_command_line contains "Invoke-Command" or action_process_image_command_line contains "Invoke-Expression")) and (((action_process_image_path endswith "\\InstallUtil.exe" or action_process_image_path endswith "\\RegAsm.exe" or action_process_image_path endswith "\\RegSvcs.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe")) or ((action_process_image_name = "InstallUtil.exe" or action_process_image_name = "RegAsm.exe" or action_process_image_name = "RegSvcs.exe" or action_process_image_name = "REGSVR32.EXE" or action_process_image_name = "RUNDLL32.EXE"))))
