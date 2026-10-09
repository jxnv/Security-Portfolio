// Title: Suspicious Volume Shadow Copy Vssapi.dll Load
// ID: 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8
// Status: test
// Level: high
// Author: frack113
// Date: 2022-10-31
// Tags: attack.impact, attack.t1490
// Description: Detects the image load of VSS DLL by uncommon executables
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\vssapi.dll") and not (((action_process_image_path = null) or ((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\")) or (((action_process_image_path = "C:\\Windows\\explorer.exe" or action_process_image_path = "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe" or action_process_image_path = "C:\\Windows\\servicing\\TrustedInstaller.exe")) or ((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\Temp\\{" or action_process_image_path startswith "C:\\Windows\\WinSxS\\" or action_process_image_path startswith "C:\\$WinREAgent\\Scratch\\"))))) and not ((((action_process_image_path contains "\\temp\\is-" and action_process_image_path contains "\\avira_system_speedup.tmp")) or (action_process_image_path startswith "C:\\ProgramData\\Package Cache\\"))))
