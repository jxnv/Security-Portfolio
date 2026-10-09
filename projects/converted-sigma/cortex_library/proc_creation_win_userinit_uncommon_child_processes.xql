// Title: Uncommon Userinit Child Process
// ID: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
// Status: test
// Level: high
// Author: Tom Ueltschi (@c_APT_ure), Tim Shelton
// Date: 2019-01-12
// Tags: attack.privilege-escalation, attack.t1037.001, attack.persistence
// Description: Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\userinit.exe") and not ((action_process_image_path endswith ":\\WINDOWS\\explorer.exe")) and not ((((action_process_image_path endswith ":\\Program Files (x86)\\Citrix\\HDX\\bin\\cmstart.exe" or action_process_image_path endswith ":\\Program Files (x86)\\Citrix\\HDX\\bin\\icast.exe" or action_process_image_path endswith ":\\Program Files (x86)\\Citrix\\System32\\icast.exe" or action_process_image_path endswith ":\\Program Files\\Citrix\\HDX\\bin\\cmstart.exe" or action_process_image_path endswith ":\\Program Files\\Citrix\\HDX\\bin\\icast.exe" or action_process_image_path endswith ":\\Program Files\\Citrix\\System32\\icast.exe")) or (action_process_image_path = null) or ((action_process_image_command_line contains "netlogon.bat" or action_process_image_command_line contains "UsrLogon.cmd")) or ((action_process_image_path endswith ":\\Windows\\System32\\proquota.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\proquota.exe")) or (action_process_image_command_line = "PowerShell.exe"))))
