// Title: Execute Files with Msdeploy.exe
// ID: 646bc99f-6682-4b47-a73a-17b1b64c9d34
// Status: test
// Level: medium
// Author: Beyu Denis, oscd.community
// Date: 2020-10-18
// Tags: attack.stealth, attack.t1218
// Description: Detects file execution using the msdeploy.exe lolbin
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "verb:sync" and action_process_image_command_line contains "-source:RunCommand" and action_process_image_command_line contains "-dest:runCommand") and action_process_image_path endswith "\\msdeploy.exe")
