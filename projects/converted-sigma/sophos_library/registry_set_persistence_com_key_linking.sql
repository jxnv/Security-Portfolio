-- Title: Potential COM Object Hijacking Via TreatAs Subkey - Registry
-- ID: 9b0f8a61-91b2-464f-aceb-0527e0a45020
-- Status: test
-- Level: medium
-- Author: Kutepov Anton, oscd.community
-- Date: 2019-10-23
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.015
-- Description: Detects COM object hijacking via TreatAs subkey
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%HKU\\%' AND TargetObject ILIKE '%Classes\\CLSID\\%' AND TargetObject ILIKE '%\\TreatAs%')) AND NOT ((Image = 'C:\\WINDOWS\\system32\\svchost.exe')))
