-- Title: MMC Spawning Windows Shell
-- ID: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
-- Status: test
-- Level: high
-- Author: Karneades, Swisscom CSIRT
-- Date: 2019-08-05
-- Tags: attack.lateral-movement, attack.t1021.003
-- Description: Detects a Windows command line executable started from MMC
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\mmc.exe') AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\regsvr32.exe')) OR (Image ILIKE '%\\BITSADMIN%')))
