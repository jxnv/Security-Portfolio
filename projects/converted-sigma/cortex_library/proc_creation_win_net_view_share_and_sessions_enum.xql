// Title: Share And Session Enumeration Using Net.EXE
// ID: 62510e69-616b-4078-b371-847da438cc03
// Status: stable
// Level: low
// Author: Endgame, JHasenbusch (ported for oscd.community)
// Date: 2018-10-30
// Tags: attack.discovery, attack.t1018
// Description: Detects attempts to enumerate file shares, printer shares and sessions using "net.exe" with the "view" flag.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "view") and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe")))) and not ((action_process_image_command_line contains "\\\\\\\\")))
