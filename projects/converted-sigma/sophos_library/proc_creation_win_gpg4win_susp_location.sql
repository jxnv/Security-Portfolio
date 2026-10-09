-- Title: File Encryption/Decryption Via Gpg4win From Suspicious Locations
-- ID: e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2022-11-30
-- Tags: attack.execution
-- Description: Detects usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%-passphrase%') AND (((Image ILIKE '%\\gpg.exe' OR Image ILIKE '%\\gpg2.exe')) OR (Product = 'GNU Privacy Guard (GnuPG)') OR (Description = 'GnuPG’s OpenPGP tool')) AND ((CommandLine ILIKE '%:\\PerfLogs\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Roaming\\%')))
