// Title: CredUI.DLL Loaded By Uncommon Process
// ID: 9ae01559-cf7e-4f8e-8e14-4c290a1b4784
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-10-20
// Tags: attack.credential-access, attack.collection, attack.t1056.002
// Description: Detects loading of "credui.dll" and related DLLs by an uncommon process. Attackers might leverage this DLL for potential use of "CredUIPromptForCredentials" or "CredUnPackAuthenticationBufferW".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((ImageLoaded endswith "\\credui.dll" or ImageLoaded endswith "\\wincredui.dll")) or ((action_process_image_name = "credui.dll" or action_process_image_name = "wincredui.dll"))) and not ((((action_process_image_path = "C:\\Windows\\explorer.exe" or action_process_image_path = "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe" or action_process_image_path = "C:\\Windows\\regedit.exe")) or ((action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\SystemApps\\")))) and not (((action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Microsoft\\OneDrive\\") or (action_process_image_path endswith "\\opera_autoupdate.exe") or ((action_process_image_path endswith "\\procexp64.exe" or action_process_image_path endswith "\\procexp64a.exe" or action_process_image_path endswith "\\procexp.exe")) or (action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Microsoft\\Teams\\" and action_process_image_path endswith "\\Teams.exe"))))
