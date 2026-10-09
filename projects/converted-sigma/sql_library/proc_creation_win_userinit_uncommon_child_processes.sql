-- Title: Uncommon Userinit Child Process
-- ID: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
-- Status: test
-- Level: high
-- Author: Tom Ueltschi (@c_APT_ure), Tim Shelton
-- Date: 2019-01-12
-- Tags: attack.privilege-escalation, attack.t1037.001, attack.persistence
-- Description: Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%\\userinit.exe') AND NOT ((Image ILIKE '%:\\WINDOWS\\explorer.exe')) AND NOT ((((Image ILIKE '%:\\Program Files (x86)\\Citrix\\HDX\\bin\\cmstart.exe' OR Image ILIKE '%:\\Program Files (x86)\\Citrix\\HDX\\bin\\icast.exe' OR Image ILIKE '%:\\Program Files (x86)\\Citrix\\System32\\icast.exe' OR Image ILIKE '%:\\Program Files\\Citrix\\HDX\\bin\\cmstart.exe' OR Image ILIKE '%:\\Program Files\\Citrix\\HDX\\bin\\icast.exe' OR Image ILIKE '%:\\Program Files\\Citrix\\System32\\icast.exe')) OR (Image IS NULL) OR ((CommandLine ILIKE '%netlogon.bat%' OR CommandLine ILIKE '%UsrLogon.cmd%')) OR ((Image ILIKE '%:\\Windows\\System32\\proquota.exe' OR Image ILIKE '%:\\Windows\\SysWOW64\\proquota.exe')) OR (CommandLine = 'PowerShell.exe'))))
