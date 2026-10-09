// Title: Registry Modification Attempt Via VBScript
// ID: 921aa10f-2e74-4cca-9498-98f9ca4d6fdf
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-08-13
// Tags: attack.persistence, attack.execution, attack.defense-impairment, attack.t1112, attack.t1059.005
// Description: Detects attempts to modify the registry using VBScript's CreateObject("Wscript.shell") and RegWrite methods via common LOLBINs.
// It could be an attempt to modify the registry for persistence without using straightforward methods like regedit.exe, reg.exe, or PowerShell.
// Threat Actors may use this technique to evade detection by security solutions that monitor for direct registry modifications through traditional tools.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "CreateObject" and action_process_image_command_line contains "Wscript.shell" and action_process_image_command_line contains ".RegWrite"))
