-- Title: MSI Installation From Suspicious Locations
-- ID: c7c8aa1c-5aff-408e-828b-998e3620b341
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-31
-- Tags: attack.execution
-- Description: Detects MSI package installation from suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Provider_Name = 'MsiInstaller' AND (EventID = '1040' OR EventID = '1042') AND (Data LIKE '%:\\Windows\\TEMP\\%' OR Data LIKE '%\\\\\\\\%' OR Data LIKE '%\\Desktop\\%' OR Data LIKE '%\\PerfLogs\\%' OR Data LIKE '%\\Users\\Public\\%')) AND NOT (((Data LIKE '%C:\\Windows\\TEMP\\UpdHealthTools.msi%') OR (Data LIKE '%\\AppData\\Local\\Temp\\WinGet\\%'))))
