-- Title: Suspicious Mstsc.EXE Execution With Local RDP File
-- ID: 6e22722b-dfb1-4508-a911-49ac840b40f8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-18
-- Tags: attack.command-and-control, attack.t1219.002
-- Description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine="*.rdp" OR CommandLine="*.rdp\"")) AND ((Image="*\\mstsc.exe") OR (OriginalFileName = 'mstsc.exe')) AND ((CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\System32\\spool\\drivers\\color%' OR CommandLine LIKE '%:\\Windows\\System32\\Tasks_Migrated %' OR CommandLine LIKE '%:\\Windows\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\Tracing\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\Downloads\\%')))
