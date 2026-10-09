-- Title: Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths
-- ID: c74c0390-3e20-41fd-a69a-128f0275a5ea
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-05
-- Tags: attack.execution
-- Description: Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%:\\PerfLogs\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\Appdata\\Local\\Temp\\%')) AND (Image ILIKE '%\\wusa.exe' AND CommandLine ILIKE '%/extract:%'))
