// Title: Potentially Suspicious Desktop Background Change Via Registry
// ID: 85b88e05-dadc-430b-8a9e-53ff1cd30aae
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Stephen Lincoln @slincoln-aiq (AttackIQ)
// Date: 2023-12-21
// Tags: attack.persistence, attack.impact, attack.defense-impairment, attack.t1112, attack.t1491.001
// Description: Detects registry value settings that would replace the user's desktop background.
// This is a common technique used by malware to change the desktop background to a ransom note or other image.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "Control Panel\\Desktop" or TargetObject contains "CurrentVersion\\Policies\\ActiveDesktop" or TargetObject contains "CurrentVersion\\Policies\\System")) and ((TargetObject endswith "NoChangingWallpaper" and Details = "DWORD (0x00000001)") or (TargetObject endswith "\\Wallpaper") or (TargetObject endswith "\\WallpaperStyle" and Details = "2")) and not (((TargetObject endswith "\\Control Panel\\Desktop\\Wallpaper" and Details = "(Empty)") or (action_process_image_path endswith "C:\\Windows\\Explorer.EXE") or (action_process_image_path endswith "\\svchost.exe"))) and not (((action_process_image_path = "C:\\Program Files\\Amazon\\EC2Launch\\EC2Launch.exe" or action_process_image_path = "C:\\Program Files (x86)\\Amazon\\EC2Launch\\EC2Launch.exe") and TargetObject endswith "\\Control Panel\\Desktop\\Wallpaper")))
