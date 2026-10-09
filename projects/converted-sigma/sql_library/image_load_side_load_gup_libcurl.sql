-- Title: Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE
-- ID: e49b5745-1064-4ac1-9a2e-f687bc2dd37e
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-05
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "libcurl.dll" by the "gup.exe" process from an uncommon location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\gup.exe' AND ImageLoaded ILIKE '%\\libcurl.dll') AND NOT ((Image ILIKE '%\\Notepad++\\updater\\GUP.exe')))
