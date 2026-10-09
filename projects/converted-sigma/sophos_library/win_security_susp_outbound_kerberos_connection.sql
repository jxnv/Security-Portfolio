-- Title: Uncommon Outbound Kerberos Connection - Security
-- ID: eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, oscd.community
-- Date: 2019-10-24
-- Tags: attack.lateral-movement, attack.credential-access, attack.t1558.003
-- Description: Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 5156 AND DestPort = 88) AND NOT (((Application ILIKE '\\device\\harddiskvolume%' OR Application ILIKE 'C:%') AND Application ILIKE '%\\Windows\\System32\\lsass.exe')) AND NOT ((((Application ILIKE '\\device\\harddiskvolume%' OR Application ILIKE 'C:%') AND (Application ILIKE '%\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe' OR Application ILIKE '%\\Program Files\\Google\\Chrome\\Application\\chrome.exe')) OR ((Application ILIKE '\\device\\harddiskvolume%' OR Application ILIKE 'C:%') AND (Application ILIKE '%\\Program Files (x86)\\Mozilla Firefox\\firefox.exe' OR Application ILIKE '%\\Program Files\\Mozilla Firefox\\firefox.exe')) OR (Application ILIKE '%\\tomcat\\bin\\tomcat8.exe'))))
