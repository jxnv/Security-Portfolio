-- Title: Uncommon Outbound Kerberos Connection
-- ID: e54979bd-c5f9-4d6c-967b-a04b19ac4c74
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, oscd.community
-- Date: 2019-10-24
-- Tags: attack.credential-access, attack.t1558, attack.lateral-movement, attack.t1550.003
-- Description: Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((DestinationPort = 88 AND Initiated = 'true') AND NOT ((Image = 'C:\\Windows\\System32\\lsass.exe')) AND NOT ((((Image = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe' OR Image = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')) OR ((Image = 'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe' OR Image = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe')) OR (Image ILIKE '%\\tomcat\\bin\\tomcat8.exe'))))
