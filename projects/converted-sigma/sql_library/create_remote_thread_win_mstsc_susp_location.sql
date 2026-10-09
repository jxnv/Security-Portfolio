-- Title: Remote Thread Creation In Mstsc.Exe From Suspicious Location
-- ID: c0aac16a-b1e7-4330-bab0-3c27bb4987c7
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-28
-- Tags: attack.credential-access
-- Description: Detects remote thread creation in the "mstsc.exe" process by a process located in a potentially suspicious location.
-- This technique is often used by attackers in order to hook some APIs used by DLLs loaded by "mstsc.exe" during RDP authentications in order to steal credentials.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetImage ILIKE '%\\mstsc.exe' AND (SourceImage ILIKE '%:\\Temp\\%' OR SourceImage ILIKE '%:\\Users\\Public\\%' OR SourceImage ILIKE '%:\\Windows\\PerfLogs\\%' OR SourceImage ILIKE '%:\\Windows\\Tasks\\%' OR SourceImage ILIKE '%:\\Windows\\Temp\\%' OR SourceImage ILIKE '%\\AppData\\Local\\Temp\\%'))
