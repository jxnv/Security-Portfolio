// Title: Suspicious Msiexec Quiet Install From Remote Location
// ID: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-28
// Tags: attack.stealth, attack.t1218.007
// Description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "-i" or action_process_image_command_line contains "/i" or action_process_image_command_line contains "-package" or action_process_image_command_line contains "/package" or action_process_image_command_line contains "-a" or action_process_image_command_line contains "/a" or action_process_image_command_line contains "-j" or action_process_image_command_line contains "/j")) and ((action_process_image_path endswith "\\msiexec.exe") or (action_process_image_name = "msiexec.exe")) and ((action_process_image_command_line contains "-q" or action_process_image_command_line contains "/q")) and ((action_process_image_command_line contains "http" or action_process_image_command_line contains "\\\\\\\\"))) and not (((action_process_image_command_line contains "\\AppData\\Local\\Temp\\OpenOffice" and action_process_image_command_line contains "Installation Files\\openoffice"))))
