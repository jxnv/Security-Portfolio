-- Title: New Netsh Helper DLL Registered From A Suspicious Location
-- ID: e7b18879-676e-4a0e-ae18-27039185a8e7
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-11-28
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.007
-- Description: Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\NetSh%') AND (((Details ILIKE '%:\\Perflogs\\%' OR Details ILIKE '%:\\Users\\Public\\%' OR Details ILIKE '%:\\Windows\\Temp\\%' OR Details ILIKE '%\\AppData\\Local\\Temp\\%' OR Details ILIKE '%\\Temporary Internet%')) OR (((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Favorites\\%')) OR ((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Favourites\\%')) OR ((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Contacts\\%')) OR ((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Pictures\\%')))))
