// Title: Windows AMSI Related Registry Tampering Via CommandLine
// ID: 7dbbcac2-57a0-45ac-b306-ff30a8bd2981
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-12-25
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects tampering of AMSI (Anti-Malware Scan Interface) related registry values via command line tools such as reg.exe or PowerShell.
// AMSI provides a generic interface for applications and services to integrate with antimalware products.
// Adversaries may disable AMSI to evade detection of malicious scripts and code execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\Software\\Microsoft\\Windows Script\\Settings" and action_process_image_command_line contains "AmsiEnable")) and ((((action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains "sp ")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")))) or ((action_process_image_command_line contains "add") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))))
