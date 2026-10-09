-- Title: UAC Bypass Using Iscsicpl - ImageLoad
-- ID: 9ed5959a-c43c-4c59-84e3-d28628429456
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-17
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects the "iscsicpl.exe" UAC bypass technique that leverages a DLL Search Order hijacking technique to load a custom DLL's from temp or a any user controlled location in the users %PATH%
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image = 'C:\\Windows\\SysWOW64\\iscsicpl.exe' AND ImageLoaded ILIKE '%\\iscsiexe.dll') AND NOT (((ImageLoaded ILIKE '%C:\\Windows\\%' AND ImageLoaded ILIKE '%iscsiexe.dll%'))))
