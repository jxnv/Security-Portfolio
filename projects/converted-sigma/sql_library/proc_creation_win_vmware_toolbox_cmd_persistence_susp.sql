-- Title: Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
-- ID: 236d8e89-ed95-4789-a982-36f4643738ba
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-14
-- Tags: attack.execution, attack.persistence, attack.t1059
-- Description: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script that's located in a potentially suspicious location to run for a specific VM state
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% script %' AND CommandLine ILIKE '% set %')) AND ((Image ILIKE '%\\VMwareToolBoxCmd.exe') OR (OriginalFileName = 'toolbox-cmd.exe')) AND ((CommandLine ILIKE '%:\\PerfLogs\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%:\\Windows\\System32\\Tasks\\%' OR CommandLine ILIKE '%:\\Windows\\Tasks\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp%')))
