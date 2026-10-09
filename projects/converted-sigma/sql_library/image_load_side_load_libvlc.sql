-- Title: Potential Libvlc.DLL Sideloading
-- ID: bf9808c4-d24f-44a2-8398-b65227d406b6
-- Status: test
-- Level: medium
-- Author: X__Junior
-- Date: 2023-04-17
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "libvlc.dll", a DLL that is legitimately used by "VLC.exe"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\libvlc.dll') AND NOT (((ImageLoaded ILIKE 'C:\\Program Files (x86)\\VideoLAN\\VLC\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\VideoLAN\\VLC\\%'))))
