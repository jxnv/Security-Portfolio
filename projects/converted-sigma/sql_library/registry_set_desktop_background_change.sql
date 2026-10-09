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

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%Control Panel\\Desktop%' OR TargetObject ILIKE '%CurrentVersion\\Policies\\ActiveDesktop%' OR TargetObject ILIKE '%CurrentVersion\\Policies\\System%')) AND ((TargetObject ILIKE '%NoChangingWallpaper' AND Details = 'DWORD (0x00000001)') OR (TargetObject ILIKE '%\\Wallpaper') OR (TargetObject ILIKE '%\\WallpaperStyle' AND Details = '2')) AND NOT (((TargetObject ILIKE '%\\Control Panel\\Desktop\\Wallpaper' AND Details = '(Empty)') OR (Image ILIKE '%C:\\Windows\\Explorer.EXE') OR (Image ILIKE '%\\svchost.exe'))) AND NOT (((Image = 'C:\\Program Files\\Amazon\\EC2Launch\\EC2Launch.exe' OR Image = 'C:\\Program Files (x86)\\Amazon\\EC2Launch\\EC2Launch.exe') AND TargetObject ILIKE '%\\Control Panel\\Desktop\\Wallpaper')))
