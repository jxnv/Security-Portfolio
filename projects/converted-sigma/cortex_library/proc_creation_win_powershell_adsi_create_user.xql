// Title: New User Account Creation Attempt Via ADSI in CommandLine
// ID: 7c9fed65-039a-4055-8c23-fa763d94aff6
// Status: experimental
// Level: medium
// Author: William Gokah (idea), Raylee Hawkins, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-08-13
// Tags: attack.persistence, attack.t1136.001, attack.t1136.002
// Description: Detects PowerShell command line arguments containing ADSI (Active Directory Service Interfaces) patterns
// trying to create a new user account via the WinNT or LDAP provider. This is an uncommon method to create
// user accounts and may indicate an attempt to evade detection by avoiding more commonly monitored commands
// such as "net user", "New-LocalUser" or "New-ADUser".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "[ADSI]") and ((action_process_image_command_line contains "WinNT://" or action_process_image_command_line contains "LDAP://")) and ((action_process_image_command_line contains ".Create(\"user" or action_process_image_command_line contains ".Create('user")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
