// Title: Potential MsiExec Masquerading
// ID: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-11-14
// Tags: attack.stealth, attack.t1036.005
// Description: Detects the execution of msiexec.exe from an uncommon directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\msiexec.exe") or (action_process_image_name = "\\msiexec.exe")) and not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\"))))
