-- Title: Windows Default Domain GPO Modification via GPME
-- ID: dcff7e85-d01f-4eb5-badd-84e2e6be8294
-- Status: experimental
-- Level: medium
-- Author: TropChaud
-- Date: 2025-11-22
-- Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
-- Description: Detects the use of the Group Policy Management Editor (GPME) to modify Default Domain or Default Domain Controllers Group Policy Objects (GPOs).
-- Adversaries may leverage GPME to make stealthy changes in these default GPOs to deploy malicious GPOs configurations across the domain without raising suspicion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%31B2F340-016D-11D2-945F-00C04FB984F9%' OR CommandLine LIKE '%6AC1786C-016F-11D2-945F-00C04FB984F9%')) AND ((CommandLine LIKE '%gpme.msc%' AND CommandLine LIKE '%gpobject:%')) AND ((Image="*\\mmc.exe") OR (OriginalFileName = 'MMC.exe')))
