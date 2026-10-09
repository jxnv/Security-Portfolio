// Title: Windows Credential Guard Registry Tampering Via CommandLine
// ID: c17d47b7-dcd6-4109-87eb-d1817bd4cbc9
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-12-26
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects attempts to add, modify, or delete Windows Credential Guard related registry keys or values via command line tools such as Reg.exe or PowerShell.
// Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them.
// Adversaries may disable Credential Guard to gain access to sensitive credentials stored in the system, such as NTLM hashes and Kerberos tickets, which can be used for lateral movement and privilege escalation.
// The rule matches suspicious command lines that target DeviceGuard or LSA registry paths and manipulate keys like EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures, or LsaCfgFlags.
// Such activity may indicate an attempt to disable or tamper with Credential Guard, potentially exposing sensitive credentials for misuse.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add " or action_process_image_command_line contains "New-ItemProperty " or action_process_image_command_line contains "Set-ItemProperty " or action_process_image_command_line contains "si " or action_process_image_command_line contains "delete " or action_process_image_command_line contains "del " or action_process_image_command_line contains "Remove-ItemProperty " or action_process_image_command_line contains "rp ")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))) and ((action_process_image_command_line contains "\\Control\\DeviceGuard" or action_process_image_command_line contains "\\Control\\LSA" or action_process_image_command_line contains "Software\\Policies\\Microsoft\\Windows\\DeviceGuard")) and ((action_process_image_command_line contains "EnableVirtualizationBasedSecurity" or action_process_image_command_line contains "RequirePlatformSecurityFeatures" or action_process_image_command_line contains "LsaCfgFlags")))
