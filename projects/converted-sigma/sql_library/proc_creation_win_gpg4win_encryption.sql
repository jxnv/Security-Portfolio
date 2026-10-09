-- Title: File Encryption Using Gpg4win
-- ID: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-09
-- Tags: attack.execution
-- Description: Detects usage of Gpg4win to encrypt files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% -c %' AND CommandLine ILIKE '%passphrase%')) AND (((Image ILIKE '%\\gpg.exe' OR Image ILIKE '%\\gpg2.exe')) OR (Description = 'GnuPG’s OpenPGP tool')))
