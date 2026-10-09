-- Title: Uncommon File Creation By Mysql Daemon Process
-- ID: c61daa90-3c1e-4f18-af62-8f288b5c9aaf
-- Status: test
-- Level: high
-- Author: Joseph Kamau
-- Date: 2024-05-27
-- Tags: attack.stealth
-- Description: Detects the creation of files with scripting or executable extensions by Mysql daemon.
-- Which could be an indicator of "User Defined Functions" abuse to download malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\mysqld.exe' OR Image ILIKE '%\\mysqld-nt.exe') AND (TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.dat' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.psm1' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs'))
