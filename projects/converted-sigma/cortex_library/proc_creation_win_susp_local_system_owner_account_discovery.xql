// Title: Local Accounts Discovery
// ID: 502b42de-4306-40b4-9596-6f590c81f073
// Status: test
// Level: low
// Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-21
// Tags: attack.discovery, attack.t1033, attack.t1087.001
// Description: Local accounts, System Owner/User discovery using operating systems utilities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains " /c" and action_process_image_command_line contains "dir " and action_process_image_command_line contains "\\Users\\")) and not ((action_process_image_command_line contains " rmdir "))) or (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe") and action_process_image_command_line contains "user") and not (((action_process_image_command_line contains "/domain" or action_process_image_command_line contains "/add" or action_process_image_command_line contains "/delete" or action_process_image_command_line contains "/active" or action_process_image_command_line contains "/expires" or action_process_image_command_line contains "/passwordreq" or action_process_image_command_line contains "/scriptpath" or action_process_image_command_line contains "/times" or action_process_image_command_line contains "/workstations")))) or ((action_process_image_path endswith "\\cmdkey.exe" and action_process_image_command_line contains " /l") or (((action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\quser.exe" or action_process_image_path endswith "\\qwinsta.exe")) or ((action_process_image_name = "whoami.exe" or action_process_image_name = "quser.exe" or action_process_image_name = "qwinsta.exe"))) or (action_process_image_path endswith "\\wmic.exe" and (action_process_image_command_line contains "useraccount" and action_process_image_command_line contains "get"))))
