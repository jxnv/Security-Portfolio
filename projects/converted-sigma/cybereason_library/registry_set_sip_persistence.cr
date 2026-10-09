// Title: Persistence Via New SIP Provider
// ID: 5a2b21ee-6aaa-4234-ac9d-59a59edf90a1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-21
// Tags: attack.persistence, attack.defense-impairment, attack.t1553.003
// Description: Detects when an attacker register a new SIP provider for persistence and defense evasion
// Converted by: Sigma Universal SIEM/EDR CLI

((((TargetObject contains "\\Dll" OR TargetObject contains "\\$DLL")) AND ((TargetObject contains "\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\" OR TargetObject contains "\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType" OR TargetObject contains "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\" OR TargetObject contains "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType"))) AND NOT ((((Details == "WINTRUST.DLL" OR Details == "mso.dll")) OR (Image == "C:\\Windows\\System32\\poqexec.exe" AND TargetObject contains "\\CryptSIPDll" AND Details == "C:\\Windows\\System32\\PsfSip.dll"))))
