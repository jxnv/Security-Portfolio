-- Title: UAC Bypass Using .NET Code Profiler on MMC
-- ID: 93a19907-d4f9-4deb-9f91-aac4692776a6
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-08-30
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects the pattern of UAC Bypass using .NET Code Profiler and mmc.exe DLL hijacking (UACMe 39)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetFilename ILIKE 'C:\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\Local\\Temp\\pe386.dll')
