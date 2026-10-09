// Title: GUI Input Capture - macOS
// ID: 60f1ce20-484e-41bd-85f4-ac4afec2c541
// Status: test
// Level: low
// Author: remotephone, oscd.community
// Date: 2020-10-13
// Tags: attack.collection, attack.credential-access, attack.t1056.002
// Description: Detects attempts to use system dialog prompts to capture user credentials
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-e" and action_process_image_command_line contains "display" and action_process_image_command_line contains "dialog" and action_process_image_command_line contains "answer")) and ((action_process_image_command_line contains "admin" or action_process_image_command_line contains "administrator" or action_process_image_command_line contains "authenticate" or action_process_image_command_line contains "authentication" or action_process_image_command_line contains "credentials" or action_process_image_command_line contains "pass" or action_process_image_command_line contains "password" or action_process_image_command_line contains "unlock")) and (action_process_image_path endswith "/osascript"))
