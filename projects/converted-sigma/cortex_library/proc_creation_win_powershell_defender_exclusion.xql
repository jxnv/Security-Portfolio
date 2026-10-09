// Title: Powershell Defender Exclusion
// ID: 17769c90-230e-488b-a463-e05c08e9d48f
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2021-04-29
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Add-MpPreference " or action_process_image_command_line contains "Set-MpPreference ")) and ((action_process_image_command_line contains " -ExclusionPath " or action_process_image_command_line contains " -ExclusionExtension " or action_process_image_command_line contains " -ExclusionProcess " or action_process_image_command_line contains " -ExclusionIpAddress ")))
