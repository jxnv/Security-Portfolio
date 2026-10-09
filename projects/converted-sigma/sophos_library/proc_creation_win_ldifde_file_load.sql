-- Title: Import LDAP Data Interchange Format File Via Ldifde.EXE
-- ID: 6f535e01-ca1f-40be-ab8d-45b19c0c8b7f
-- Status: test
-- Level: medium
-- Author: @gott_cyber
-- Date: 2022-09-02
-- Tags: attack.command-and-control, attack.stealth, attack.t1218, attack.t1105
-- Description: Detects the execution of "Ldifde.exe" with the import flag "-i". The can be abused to include HTTP-based arguments which will allow the arbitrary download of files from a remote server.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-i%' AND CommandLine ILIKE '%-f%')) AND ((Image ILIKE '%\\ldifde.exe') OR (OriginalFileName = 'ldifde.exe')))
