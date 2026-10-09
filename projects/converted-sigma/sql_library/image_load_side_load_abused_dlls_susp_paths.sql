-- Title: Abusable DLL Potential Sideloading From Suspicious Location
-- ID: 799a5f48-0ac1-4e0f-9152-71d137d48c2a
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-07-11
-- Tags: attack.execution, attack.t1059
-- Description: Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%\\coreclr.dll' OR ImageLoaded ILIKE '%\\facesdk.dll' OR ImageLoaded ILIKE '%\\HPCustPartUI.dll' OR ImageLoaded ILIKE '%\\libcef.dll' OR ImageLoaded ILIKE '%\\ZIPDLL.dll')) AND (((ImageLoaded ILIKE '%:\\Perflogs\\%' OR ImageLoaded ILIKE '%:\\Users\\Public\\%' OR ImageLoaded ILIKE '%\\Temporary Internet%' OR ImageLoaded ILIKE '%\\Windows\\Temp\\%')) OR (((ImageLoaded ILIKE '%:\\Users\\%' AND ImageLoaded ILIKE '%\\Favorites\\%')) OR ((ImageLoaded ILIKE '%:\\Users\\%' AND ImageLoaded ILIKE '%\\Favourites\\%')) OR ((ImageLoaded ILIKE '%:\\Users\\%' AND ImageLoaded ILIKE '%\\Contacts\\%')) OR ((ImageLoaded ILIKE '%:\\Users\\%' AND ImageLoaded ILIKE '%\\Pictures\\%')))))
