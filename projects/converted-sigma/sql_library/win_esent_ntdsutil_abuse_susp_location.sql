-- Title: Dump Ntds.dit To Suspicious Location
-- ID: 94dc4390-6b7c-4784-8ffc-335334404650
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-14
-- Tags: attack.execution
-- Description: Detects potential abuse of ntdsutil to dump ntds.dit database to a suspicious location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Data ILIKE '%:\\ntds.dit%' OR Data ILIKE '%\\Appdata\\%' OR Data ILIKE '%\\Desktop\\%' OR Data ILIKE '%\\Downloads\\%' OR Data ILIKE '%\\Perflogs\\%' OR Data ILIKE '%\\Temp\\%' OR Data ILIKE '%\\Users\\Public\\%')) AND (Provider_Name = 'ESENT' AND EventID = 325 AND Data ILIKE '%ntds.dit%'))
