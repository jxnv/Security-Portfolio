// Title: Shadow Copies Deletion Using Operating Systems Utilities
// ID: c947b146-0abc-4c87-9c64-b17e9d7274a2
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
// Date: 2019-10-22
// Tags: attack.impact, attack.stealth, attack.t1070, attack.t1490
// Description: Shadow Copies deletion using operating systems utilities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "shadow" and action_process_image_command_line contains "delete")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\vssadmin.exe" or action_process_image_path endswith "\\diskshadow.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "wmic.exe" or action_process_image_name = "VSSADMIN.EXE" or action_process_image_name = "diskshadow.exe")))) or (((action_process_image_command_line contains "delete" and action_process_image_command_line contains "catalog" and action_process_image_command_line contains "quiet")) and ((action_process_image_path endswith "\\wbadmin.exe") or (action_process_image_name = "WBADMIN.EXE"))) or (((action_process_image_command_line contains "resize" and action_process_image_command_line contains "shadowstorage") and (action_process_image_command_line contains "unbounded" or action_process_image_command_line contains "/MaxSize=")) and ((action_process_image_path endswith "\\vssadmin.exe") or (action_process_image_name = "VSSADMIN.EXE"))))
