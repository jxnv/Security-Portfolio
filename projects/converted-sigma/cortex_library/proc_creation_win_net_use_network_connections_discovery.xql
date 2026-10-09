// Title: System Network Connections Discovery Via Net.EXE
// ID: 1c67a717-32ba-409b-a45d-0fb704a73a81
// Status: test
// Level: low
// Author: frack113
// Date: 2021-12-10
// Tags: attack.discovery, attack.t1049
// Description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line endswith " use" or action_process_image_command_line endswith " sessions")) or ((action_process_image_command_line contains " use " or action_process_image_command_line contains " sessions "))) and (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))))
