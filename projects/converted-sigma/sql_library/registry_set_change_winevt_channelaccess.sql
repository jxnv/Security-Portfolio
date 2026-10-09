-- Title: Change Winevt Channel Access Permission Via Registry
-- ID: 7d9263bd-dc47-4a58-bc92-5474abab390c
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-09-17
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects tampering with the "ChannelAccess" registry key in order to change access to Windows event channel.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\%' AND TargetObject ILIKE '%\\ChannelAccess' AND (Details ILIKE '%(A;;0x1;;;LA)%' OR Details ILIKE '%(A;;0x1;;;SY)%' OR Details ILIKE '%(A;;0x5;;;BA)%')) AND NOT (((Image ILIKE 'C:\\Windows\\WinSxS\\%' AND Image ILIKE '%\\TiWorker.exe') OR (Image = 'C:\\Windows\\servicing\\TrustedInstaller.exe'))))
