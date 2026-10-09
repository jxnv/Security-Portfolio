// Title: WSL Kali-Linux Usage
// ID: 6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-10-10
// Tags: attack.stealth, attack.t1202
// Description: Detects the use of Kali Linux through Windows Subsystem for Linux
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\AppData\\Local\\packages\\KaliLinux")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe"))) or (action_process_image_path contains ":\\Program Files\\WindowsApps\\KaliLinux." and action_process_image_path endswith "\\kali.exe")) or (((((action_process_image_path contains "\\kali.exe" or action_process_image_path contains "\\KaliLinux")) or ((action_process_image_command_line contains "Kali.exe" or action_process_image_command_line contains "Kali-linux" or action_process_image_command_line contains "kalilinux"))) and ((actor_process_image_path endswith "\\wsl.exe" or actor_process_image_path endswith "\\wslhost.exe"))) and not (((action_process_image_command_line contains " -i " or action_process_image_command_line contains " --install " or action_process_image_command_line contains " --unregister ")))))
