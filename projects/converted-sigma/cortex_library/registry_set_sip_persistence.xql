// Title: Persistence Via New SIP Provider
// ID: 5a2b21ee-6aaa-4234-ac9d-59a59edf90a1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-21
// Tags: attack.persistence, attack.defense-impairment, attack.t1553.003
// Description: Detects when an attacker register a new SIP provider for persistence and defense evasion
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((TargetObject contains "\\Dll" or TargetObject contains "\\$DLL")) and ((TargetObject contains "\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType" or TargetObject contains "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\" or TargetObject contains "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType"))) and not ((((Details = "WINTRUST.DLL" or Details = "mso.dll")) or (action_process_image_path = "C:\\Windows\\System32\\poqexec.exe" and TargetObject contains "\\CryptSIPDll" and Details = "C:\\Windows\\System32\\PsfSip.dll"))))
