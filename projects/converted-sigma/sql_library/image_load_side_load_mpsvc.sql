-- Title: Potential DLL Sideloading Of MpSvc.DLL
-- ID: 5ba243e5-8165-4cf7-8c69-e1d3669654c1
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema
-- Date: 2024-07-11
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "MpSvc.dll".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\MpSvc.dll') AND NOT (((ImageLoaded ILIKE 'C:\\Program Files\\Windows Defender\\%' OR ImageLoaded ILIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\%' OR ImageLoaded ILIKE 'C:\\Windows\\WinSxS\\%'))))
