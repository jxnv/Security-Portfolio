// Title: Potential Active Directory Enumeration Using AD Module - ProcCreation
// ID: 70bc5215-526f-4477-963c-a47a5c9ebd12
// Status: test
// Level: medium
// Author: frack113
// Date: 2023-01-22
// Tags: attack.reconnaissance, attack.discovery, attack.impact
// Description: Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Import-Module " or action_process_image_command_line contains "ipmo ")) and (action_process_image_command_line contains "Microsoft.ActiveDirectory.Management.dll") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
