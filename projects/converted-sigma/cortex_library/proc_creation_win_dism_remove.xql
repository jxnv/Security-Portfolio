// Title: Dism Remove Online Package
// ID: 43e32da2-fdd0-4156-90de-50dfd62636f9
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-16
// Tags: attack.defense-impairment, attack.t1685
// Description: Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\Dism.exe" and (action_process_image_command_line contains "/Online" and action_process_image_command_line contains "/Disable-Feature")) or (action_process_image_path endswith "\\DismHost.exe" and (actor_process_command_line contains "/Online" and actor_process_command_line contains "/Disable-Feature")))
