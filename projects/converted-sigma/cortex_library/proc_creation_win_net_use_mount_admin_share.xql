// Title: Windows Admin Share Mount Via Net.EXE
// ID: 3abd6094-7027-475f-9630-8ab9be7b9725
// Status: test
// Level: medium
// Author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga
// Date: 2020-10-05
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects when an admin share is mounted using net.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " use " and action_process_image_command_line contains " \\\\\\\\*\\\\*$")) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
