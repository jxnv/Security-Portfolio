-- Title: Uncommon FileSystem Load Attempt By Format.com
-- ID: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-04
-- Tags: attack.stealth
-- Description: Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\format.com' AND CommandLine ILIKE '%/fs:%') AND NOT (((CommandLine ILIKE '%/fs:exFAT%' OR CommandLine ILIKE '%/fs:FAT%' OR CommandLine ILIKE '%/fs:NTFS%' OR CommandLine ILIKE '%/fs:ReFS%' OR CommandLine ILIKE '%/fs:UDF%'))))
