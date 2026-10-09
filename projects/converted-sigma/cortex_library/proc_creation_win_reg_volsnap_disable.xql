// Title: Disabled Volume Snapshots
// ID: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-01-28
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects commands that temporarily turn off Volume Snapshots
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\Services\\VSS\\Diag" and action_process_image_command_line contains "/d Disabled"))
