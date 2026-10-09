// Title: IIS Native-Code Module Command Line Installation
// ID: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-12-11
// Tags: attack.persistence, attack.t1505.003
// Description: Detects suspicious IIS native-code module installations via command line
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "install" and action_process_image_command_line contains "module") and (action_process_image_command_line contains "-name:" or action_process_image_command_line contains "/name:")) and ((action_process_image_path endswith "\\appcmd.exe") or (action_process_image_name = "appcmd.exe"))) and not ((actor_process_image_path = "C:\\Windows\\System32\\inetsrv\\iissetup.exe")))
