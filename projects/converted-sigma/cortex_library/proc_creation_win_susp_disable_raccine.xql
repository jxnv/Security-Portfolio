// Title: Raccine Uninstall
// ID: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-01-21
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "taskkill " and action_process_image_command_line contains "RaccineSettings.exe")) or ((action_process_image_command_line contains "reg.exe" and action_process_image_command_line contains "delete" and action_process_image_command_line contains "Raccine Tray")) or ((action_process_image_command_line contains "schtasks" and action_process_image_command_line contains "/DELETE" and action_process_image_command_line contains "Raccine Rules Updater")))
