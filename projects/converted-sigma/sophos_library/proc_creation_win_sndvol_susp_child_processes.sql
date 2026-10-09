-- Title: Uncommon Child Processes Of SndVol.exe
-- ID: ba42babc-0666-4393-a4f7-ceaf5a69191e
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-06-09
-- Tags: attack.execution
-- Description: Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\SndVol.exe') AND NOT ((Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '% shell32.dll,Control_RunDLL %')))
