// Title: ShimCache Flush
// ID: b0524451-19af-4efa-a46f-562a977f792e
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-02-01
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects actions that clear the local ShimCache and remove forensic evidence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "rundll32" and action_process_image_command_line contains "apphelp.dll")) and ((action_process_image_command_line contains "ShimFlushCache" or action_process_image_command_line contains "#250"))) or (((action_process_image_command_line contains "rundll32" and action_process_image_command_line contains "kernel32.dll")) and ((action_process_image_command_line contains "BaseFlushAppcompatCache" or action_process_image_command_line contains "#46"))))
