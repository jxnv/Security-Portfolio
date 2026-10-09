-- Title: File Decryption Using Gpg4win
-- ID: 037dcd71-33a8-4392-bb01-293c94663e5a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-09
-- Tags: attack.execution
-- Description: Detects usage of Gpg4win to decrypt files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% -d %' AND CommandLine ILIKE '%passphrase%')) AND (((Image ILIKE '%\\gpg.exe' OR Image ILIKE '%\\gpg2.exe')) OR (Description = 'GnuPG’s OpenPGP tool')))
