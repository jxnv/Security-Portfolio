-- Title: Clfs.SYS Loaded By Process Located In a Potential Suspicious Location
-- ID: fb4e2211-6d08-426b-8e6f-0d4a161e3b1d
-- Status: experimental
-- Level: medium
-- Author: X__Junior
-- Date: 2025-01-20
-- Tags: attack.execution, attack.t1059
-- Description: Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ImageLoaded="*\\clfs.sys") AND (((Image LIKE '%:\\Perflogs\\%' OR Image LIKE '%:\\Users\\Public\\%' OR Image LIKE '%\\Temporary Internet%' OR Image LIKE '%\\Windows\\Temp\\%')) OR (((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\Favorites\\%')) OR ((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\Favourites\\%')) OR ((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\Contacts\\%')) OR ((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\Pictures\\%')))))
