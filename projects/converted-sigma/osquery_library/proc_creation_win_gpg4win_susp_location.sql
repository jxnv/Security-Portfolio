-- Title: File Encryption/Decryption Via Gpg4win From Suspicious Locations
-- ID: e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2022-11-30
-- Tags: attack.execution
-- Description: Detects usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%-passphrase%') AND (((Image="*\\gpg.exe" OR Image="*\\gpg2.exe")) OR (Product = 'GNU Privacy Guard (GnuPG)') OR (Description = 'GnuPG’s OpenPGP tool')) AND ((CommandLine LIKE '%:\\PerfLogs\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%')))
