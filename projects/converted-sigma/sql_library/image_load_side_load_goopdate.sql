-- Title: Potential Goopdate.DLL Sideloading
-- ID: b6188d2f-b3c4-4d2c-a17d-9706e0851af0
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "goopdate.dll", a DLL used by googleupdate.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\goopdate.dll') AND NOT (((ImageLoaded ILIKE 'C:\\Program Files (x86)\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\%'))) AND NOT ((((Image ILIKE '%\\AppData\\Local\\Temp\\GUM%' AND Image ILIKE '%.tmp\\Dropbox%') AND (ImageLoaded ILIKE '%\\AppData\\Local\\Temp\\GUM%' AND ImageLoaded ILIKE '%.tmp\\goopdate.dll%')) OR ((Image ILIKE '%\\AppData\\Local\\Temp\\GUM%' OR Image ILIKE '%:\\Windows\\SystemTemp\\GUM%') AND Image ILIKE '%.tmp\\GoogleUpdate.exe' AND (ImageLoaded ILIKE '%\\AppData\\Local\\Temp\\GUM%' OR ImageLoaded ILIKE '%:\\Windows\\SystemTemp\\GUM%')))))
