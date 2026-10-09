// Title: PowerShell AppLocker Policy Discovery Via Get-AppLockerPolicy
// ID: f14b1e99-5e53-4598-98dc-6f20ad7b35e0
// Status: experimental
// Level: low
// Author: Tom3306
// Date: 2026-08-19
// Tags: attack.discovery, attack.t1518.001
// Description: Detects AppLocker policy enumeration attempts via PowerShell using the Get-AppLockerPolicy cmdlet and an policy scope of either Effective, LDAP, or Local.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Get-AppLockerPolicy") and ((action_process_image_command_line contains " -Effective" or action_process_image_command_line contains " -Ldap " or action_process_image_command_line contains " -Local")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
