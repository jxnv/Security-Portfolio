// Title: Vulnerable Driver Blocklist Registry Tampering Via CommandLine
// ID: 22154f0e-5132-4a54-aa78-cc62f6def531
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-26
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects tampering of the Vulnerable Driver Blocklist registry via command line tools such as PowerShell or REG.EXE.
// The Vulnerable Driver Blocklist is a security feature that helps prevent the loading of known vulnerable drivers.
// Disabling this feature may indicate an attempt to bypass security controls, often targeted by threat actors
// to facilitate the installation of malicious or vulnerable drivers, particularly in scenarios involving Endpoint Detection and Response
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add " or action_process_image_command_line contains "New-ItemProperty " or action_process_image_command_line contains "Set-ItemProperty " or action_process_image_command_line contains "si ")) and ((action_process_image_command_line contains "\\Control\\CI\\Config" and action_process_image_command_line contains "VulnerableDriverBlocklistEnable")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))))
