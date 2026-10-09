-- Title: Suspicious BitLocker Access Agent Update Utility Execution
-- ID: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
-- Status: experimental
-- Level: high
-- Author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-10-18
-- Tags: attack.stealth, attack.t1218, attack.lateral-movement, attack.t1021.003
-- Description: Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
-- Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\baaupdate.exe' AND (Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe'))
