-- Title: Persistence Via New SIP Provider
-- ID: 5a2b21ee-6aaa-4234-ac9d-59a59edf90a1
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-21
-- Tags: attack.persistence, attack.defense-impairment, attack.t1553.003
-- Description: Detects when an attacker register a new SIP provider for persistence and defense evasion
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((TargetObject LIKE '%\\Dll%' OR TargetObject LIKE '%\\$DLL%')) AND ((TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType%' OR TargetObject LIKE '%\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\%' OR TargetObject LIKE '%\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType%'))) AND NOT ((((Details = 'WINTRUST.DLL' OR Details = 'mso.dll')) OR (Image = 'C:\\Windows\\System32\\poqexec.exe' AND TargetObject LIKE '%\\CryptSIPDll%' AND Details = 'C:\\Windows\\System32\\PsfSip.dll'))))
