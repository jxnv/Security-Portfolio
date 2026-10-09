-- Title: Potentially Suspicious Desktop Background Change Via Registry
-- ID: 85b88e05-dadc-430b-8a9e-53ff1cd30aae
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Stephen Lincoln @slincoln-aiq (AttackIQ)
-- Date: 2023-12-21
-- Tags: attack.persistence, attack.impact, attack.defense-impairment, attack.t1112, attack.t1491.001
-- Description: Detects registry value settings that would replace the user's desktop background.
-- This is a common technique used by malware to change the desktop background to a ransom note or other image.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%Control Panel\\Desktop%' OR TargetObject LIKE '%CurrentVersion\\Policies\\ActiveDesktop%' OR TargetObject LIKE '%CurrentVersion\\Policies\\System%')) AND ((TargetObject="*NoChangingWallpaper" AND Details = 'DWORD (0x00000001)') OR (TargetObject="*\\Wallpaper") OR (TargetObject="*\\WallpaperStyle" AND Details = '2')) AND NOT (((TargetObject="*\\Control Panel\\Desktop\\Wallpaper" AND Details = '(Empty)') OR (Image="*C:\\Windows\\Explorer.EXE") OR (Image="*\\svchost.exe"))) AND NOT (((Image = 'C:\\Program Files\\Amazon\\EC2Launch\\EC2Launch.exe' OR Image = 'C:\\Program Files (x86)\\Amazon\\EC2Launch\\EC2Launch.exe') AND TargetObject="*\\Control Panel\\Desktop\\Wallpaper")))
