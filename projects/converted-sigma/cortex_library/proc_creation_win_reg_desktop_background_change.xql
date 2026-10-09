// Title: Potentially Suspicious Desktop Background Change Using Reg.EXE
// ID: 8cbc9475-8d05-4e27-9c32-df960716c701
// Status: test
// Level: medium
// Author: Stephen Lincoln @slincoln-aiq (AttackIQ)
// Date: 2023-12-21
// Tags: attack.persistence, attack.impact, attack.defense-impairment, attack.t1112, attack.t1491.001
// Description: Detects the execution of "reg.exe" to alter registry keys that would replace the user's desktop background.
// This is a common technique used by malware to change the desktop background to a ransom note or other image.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe"))) and ((action_process_image_command_line contains "Control Panel\\Desktop" or action_process_image_command_line contains "CurrentVersion\\Policies\\ActiveDesktop" or action_process_image_command_line contains "CurrentVersion\\Policies\\System")) and (((action_process_image_command_line contains "/v NoChangingWallpaper" and action_process_image_command_line contains "/d 1")) or ((action_process_image_command_line contains "/v Wallpaper" and action_process_image_command_line contains "/t REG_SZ")) or ((action_process_image_command_line contains "/v WallpaperStyle" and action_process_image_command_line contains "/d 2"))))
