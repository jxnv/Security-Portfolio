// Title: PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'
// ID: 1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e
// Status: experimental
// Level: high
// Author: Matt Anderson (Huntress)
// Date: 2025-07-11
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9').
// This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level.
// An attacker might use this technique via the command line to bypass defenses before executing payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-LowThreatDefaultAction" or action_process_image_command_line contains "-ModerateThreatDefaultAction" or action_process_image_command_line contains "-HighThreatDefaultAction" or action_process_image_command_line contains "-SevereThreatDefaultAction" or action_process_image_command_line contains "-ltdefac " or action_process_image_command_line contains "-mtdefac " or action_process_image_command_line contains "-htdefac " or action_process_image_command_line contains "-stdefac ")) and (action_process_image_command_line contains "Set-MpPreference") and ((action_process_image_command_line contains "Allow" or action_process_image_command_line contains "6" or action_process_image_command_line contains "NoAction" or action_process_image_command_line contains "9")))
