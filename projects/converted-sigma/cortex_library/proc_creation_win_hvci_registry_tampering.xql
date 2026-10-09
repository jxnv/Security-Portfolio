// Title: Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine
// ID: 6225c53a-a96e-4235-b28f-8d7997cd96eb
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-26
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the tampering of Hypervisor-protected Code Integrity (HVCI) related registry values via command line tool reg.exe.
// HVCI uses virtualization-based security to protect code integrity by ensuring that only trusted code can run in kernel mode.
// Adversaries may tamper with HVCI to load malicious or unsigned drivers, which can be used to escalate privileges, maintain persistence, or evade security mechanisms.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add " or action_process_image_command_line contains "New-ItemProperty " or action_process_image_command_line contains "Set-ItemProperty " or action_process_image_command_line contains "si ")) and (action_process_image_command_line contains "\\DeviceGuard") and ((action_process_image_command_line contains "EnableVirtualizationBasedSecurity" or action_process_image_command_line contains "HypervisorEnforcedCodeIntegrity")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))))
