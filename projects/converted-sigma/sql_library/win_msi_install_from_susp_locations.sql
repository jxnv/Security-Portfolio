-- Title: MSI Installation From Suspicious Locations
-- ID: c7c8aa1c-5aff-408e-828b-998e3620b341
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-31
-- Tags: attack.execution
-- Description: Detects MSI package installation from suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Provider_Name = 'MsiInstaller' AND (EventID = 1040 OR EventID = 1042) AND (Data ILIKE '%:\\Windows\\TEMP\\%' OR Data ILIKE '%\\\\\\\\%' OR Data ILIKE '%\\Desktop\\%' OR Data ILIKE '%\\PerfLogs\\%' OR Data ILIKE '%\\Users\\Public\\%')) AND NOT (((Data ILIKE '%C:\\Windows\\TEMP\\UpdHealthTools.msi%') OR (Data ILIKE '%\\AppData\\Local\\Temp\\WinGet\\%'))))
