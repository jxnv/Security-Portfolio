-- Title: Credential Manager Access By Uncommon Applications
-- ID: 407aecb1-e762-4acf-8c7b-d087bcff3bb6
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-11
-- Tags: attack.t1003, attack.credential-access
-- Description: Detects suspicious processes based on name and location that access the windows credential manager and vault.
-- Which can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::cred" function
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((FileName ILIKE '%\\AppData\\Local\\Microsoft\\Credentials\\%' OR FileName ILIKE '%\\AppData\\Roaming\\Microsoft\\Credentials\\%' OR FileName ILIKE '%\\AppData\\Local\\Microsoft\\Vault\\%' OR FileName ILIKE '%\\ProgramData\\Microsoft\\Vault\\%')) AND NOT (((Image = 'C:\\Windows\\explorer.exe') OR ((Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%' OR Image ILIKE 'C:\\Windows\\system32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%')))))
