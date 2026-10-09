-- Title: Suspicious Creation with Colorcpl
-- ID: e15b518d-b4ce-4410-a9cd-501f23ce4a18
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-01-21
-- Tags: attack.stealth, attack.t1564
-- Description: Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\colorcpl.exe') AND NOT (((TargetFilename ILIKE '%.icm' OR TargetFilename ILIKE '%.gmmp' OR TargetFilename ILIKE '%.cdmp' OR TargetFilename ILIKE '%.camp'))))
