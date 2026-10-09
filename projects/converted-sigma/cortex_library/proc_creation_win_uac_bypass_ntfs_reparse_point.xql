// Title: UAC Bypass Using NTFS Reparse Point - Process
// ID: 39ed3c80-e6a1-431b-9df3-911ac53d08a7
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-30
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line startswith "\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users\\" and action_process_image_command_line endswith "\\AppData\\Local\\Temp\\update.msu" and (IntegrityLevel = "High" or IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384" or IntegrityLevel = "S-1-16-12288")) or (actor_process_command_line = "\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck" and (IntegrityLevel = "High" or IntegrityLevel = "System") and (action_process_image_command_line contains "C:\\Users\\" and action_process_image_command_line contains "\\AppData\\Local\\Temp\\" and action_process_image_command_line contains "\\dismhost.exe {") and action_process_image_path endswith "\\DismHost.exe"))
