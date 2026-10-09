// Title: New Service Creation Using Sc.EXE
// ID: 85ff530b-261d-48c6-a441-facaa2e81e48
// Status: test
// Level: low
// Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
// Date: 2023-02-20
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects the creation of a new service using the "sc.exe" utility.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\sc.exe" and (action_process_image_command_line contains "create" and action_process_image_command_line contains "binPath")) and not (((actor_process_image_path startswith "C:\\Program Files (x86)\\Dropbox\\Client\\" or actor_process_image_path startswith "C:\\Program Files\\Dropbox\\Client\\") and actor_process_image_path endswith "\\Dropbox.exe")))
