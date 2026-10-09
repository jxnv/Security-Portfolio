// Title: New User Created Via Net.EXE
// ID: cd219ff3-fa99-45d4-8380-a7d15116c6dc
// Status: test
// Level: medium
// Author: Endgame, JHasenbusch (adapted to Sigma for oscd.community)
// Date: 2018-10-30
// Tags: attack.persistence, attack.t1136.001
// Description: Identifies the creation of local users via the net.exe command.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "user" and action_process_image_command_line contains "add")) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
