// Title: Potential PowerShell Execution Policy Tampering
// ID: fad91067-08c5-4d1a-8d8c-d96a21b37814
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.defense-impairment
// Description: Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject endswith "\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy" or TargetObject endswith "\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy") and (Details contains "Bypass" or Details contains "Unrestricted")) and not (((action_process_image_path contains ":\\Windows\\System32\\" or action_process_image_path contains ":\\Windows\\SysWOW64\\"))))
