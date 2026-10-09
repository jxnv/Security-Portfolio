// Title: Always Install Elevated Windows Installer
// ID: cd951fdc-4b2f-47f5-ba99-a33bf61e3770
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
// Date: 2020-10-13
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path contains "\\Windows\\Installer\\" and action_process_image_path contains "msi") and action_process_image_path endswith "tmp") or (action_process_image_path endswith "\\msiexec.exe" and (IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384"))) and ((action_process_username contains "AUTHORI" or action_process_username contains "AUTORI")) and not ((((actor_process_image_path startswith "C:\\Program Files\\Avast Software\\" or actor_process_image_path startswith "C:\\Program Files (x86)\\Avast Software\\")) or (actor_process_image_path startswith "C:\\ProgramData\\Avira\\") or ((actor_process_image_path startswith "C:\\Program Files\\Google\\Update\\" or actor_process_image_path startswith "C:\\Program Files (x86)\\Google\\Update\\")) or (actor_process_image_path = "C:\\Windows\\System32\\services.exe") or ((action_process_image_command_line endswith "\\system32\\msiexec.exe /V") or (actor_process_command_line endswith "\\system32\\msiexec.exe /V")) or (actor_process_image_path startswith "C:\\ProgramData\\Sophos\\"))))
