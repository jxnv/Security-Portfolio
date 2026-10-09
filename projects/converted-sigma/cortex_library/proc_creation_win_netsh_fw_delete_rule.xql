// Title: Firewall Rule Deleted Via Netsh.EXE
// ID: 1a5fefe6-734f-452e-a07d-fc1c35bce4b2
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-08-14
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "firewall" and action_process_image_command_line contains "delete ")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe"))) and not (((actor_process_image_path endswith "\\instup.exe" and action_process_image_command_line contains "advfirewall firewall delete rule name=\"Avast Antivirus Admin Client\"") or (actor_process_image_path endswith "\\Dropbox.exe" and action_process_image_command_line contains "name=Dropbox"))))
